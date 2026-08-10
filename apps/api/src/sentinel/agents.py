import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    AgentEnrollment,
    AgentMetric,
    AuditEvent,
    Device,
    InstalledPackage,
    Session,
    User,
)
from sentinel.security import create_secret, hash_secret

router = APIRouter(prefix="/api/v1/agents", tags=["endpoint agents"])


class EnrollmentInput(BaseModel):
    device_id: uuid.UUID


class EnrollmentView(BaseModel):
    enrollment_token: str
    expires_at: datetime


class ClaimInput(BaseModel):
    enrollment_token: str = Field(min_length=32, max_length=200)
    version: str = Field(min_length=1, max_length=40)
    platform: str = Field(min_length=1, max_length=40)


class ClaimView(BaseModel):
    agent_id: uuid.UUID
    agent_token: str


class PackageInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=255)
    architecture: str | None = Field(default=None, max_length=50)
    manager: str = Field(min_length=1, max_length=30)


class HeartbeatInput(BaseModel):
    version: str = Field(min_length=1, max_length=40)
    cpu_percent: int = Field(ge=0, le=100)
    memory_percent: int = Field(ge=0, le=100)
    memory_used_bytes: int = Field(ge=0)
    memory_total_bytes: int = Field(ge=1)
    disk_percent: int = Field(ge=0, le=100)
    disk_free_bytes: int = Field(ge=0)
    disk_total_bytes: int = Field(ge=1)
    uptime_seconds: int = Field(ge=0)
    packages: list[PackageInput] | None = Field(default=None, max_length=20_000)


class AgentView(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    device_name: str
    version: str
    platform: str
    last_heartbeat_at: datetime | None
    connected: bool
    cpu_percent: int | None
    memory_percent: int | None
    disk_percent: int | None
    disk_free_bytes: int | None
    uptime_seconds: int | None
    package_count: int


async def authenticated_agent(
    database: Annotated[AsyncSession, Depends(get_session)],
    authorization: Annotated[str | None, Header()] = None,
) -> Agent:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "agent authentication required")
    token = authorization[7:].strip()
    agent = await database.scalar(
        select(Agent).where(
            Agent.credential_fingerprint == hash_secret(token), Agent.revoked_at.is_(None)
        )
    )
    if agent is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent credential")
    return agent


@router.post("/enrollments", response_model=EnrollmentView, status_code=201)
async def create_enrollment(
    payload: EnrollmentInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> EnrollmentView:
    device = await database.get(Device, payload.device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    existing = await database.scalar(
        select(Agent).where(Agent.device_id == device.id, Agent.revoked_at.is_(None))
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "this device already has an active agent")
    token, expires = create_secret(), datetime.now(UTC) + timedelta(minutes=30)
    database.add(
        AgentEnrollment(
            device_id=device.id,
            token_hash=hash_secret(token),
            expires_at=expires,
            created_by=auth[0].id,
        )
    )
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="agent.enrollment.create",
            target_type="device",
            target_id=str(device.id),
        )
    )
    await database.commit()
    return EnrollmentView(enrollment_token=token, expires_at=expires)


@router.post("/claim", response_model=ClaimView, status_code=201)
async def claim_enrollment(
    payload: ClaimInput,
    database: Annotated[AsyncSession, Depends(get_session)],
) -> ClaimView:
    enrollment = await database.scalar(
        select(AgentEnrollment)
        .where(
            AgentEnrollment.token_hash == hash_secret(payload.enrollment_token),
            AgentEnrollment.used_at.is_(None),
            AgentEnrollment.expires_at > datetime.now(UTC),
        )
        .with_for_update()
    )
    if enrollment is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired enrollment token")
    existing = await database.scalar(select(Agent).where(Agent.device_id == enrollment.device_id))
    if existing is not None and existing.revoked_at is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "device already has an active agent")
    token = create_secret()
    if existing is None:
        agent = Agent(
            device_id=enrollment.device_id,
            version=payload.version,
            platform=payload.platform,
            credential_fingerprint=hash_secret(token),
        )
        database.add(agent)
    else:
        agent = existing
        agent.version = payload.version
        agent.platform = payload.platform
        agent.credential_fingerprint = hash_secret(token)
        agent.revoked_at = None
    enrollment.used_at = datetime.now(UTC)
    await database.commit()
    return ClaimView(agent_id=agent.id, agent_token=token)


@router.post("/heartbeat", status_code=204)
async def heartbeat(
    payload: HeartbeatInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    agent: Annotated[Agent, Depends(authenticated_agent)],
) -> None:
    now = datetime.now(UTC)
    if agent.last_heartbeat_at and agent.last_heartbeat_at > now - timedelta(seconds=5):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "heartbeat rate limit exceeded")
    agent.version = payload.version
    agent.last_heartbeat_at = now
    database.add(
        AgentMetric(
            agent_id=agent.id,
            cpu_percent=payload.cpu_percent,
            memory_percent=payload.memory_percent,
            memory_used_bytes=payload.memory_used_bytes,
            memory_total_bytes=payload.memory_total_bytes,
            disk_percent=payload.disk_percent,
            disk_free_bytes=payload.disk_free_bytes,
            disk_total_bytes=payload.disk_total_bytes,
            uptime_seconds=payload.uptime_seconds,
            collected_at=now,
        )
    )
    device = await database.get(Device, agent.device_id)
    if device is not None:
        device.status = "online"
        device.last_seen_at = now
    if payload.packages is not None:
        await database.execute(
            delete(InstalledPackage).where(InstalledPackage.agent_id == agent.id)
        )
        unique_packages = {item.name: item for item in payload.packages}
        database.add_all(
            InstalledPackage(agent_id=agent.id, observed_at=now, **item.model_dump())
            for item in unique_packages.values()
        )
    await database.commit()


@router.get("", response_model=list[AgentView])
async def list_agents(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[AgentView]:
    rows = (
        await database.execute(
            select(Agent, Device)
            .join(Device, Device.id == Agent.device_id)
            .where(Agent.revoked_at.is_(None))
            .order_by(Device.display_name)
        )
    ).all()
    now = datetime.now(UTC)
    result = []
    for agent, device in rows:
        metric = await database.scalar(
            select(AgentMetric)
            .where(AgentMetric.agent_id == agent.id)
            .order_by(AgentMetric.collected_at.desc())
            .limit(1)
        )
        package_count = await database.scalar(
            select(func.count(InstalledPackage.id)).where(InstalledPackage.agent_id == agent.id)
        )
        result.append(
            AgentView(
                id=agent.id,
                device_id=device.id,
                device_name=device.display_name,
                version=agent.version,
                platform=agent.platform,
                last_heartbeat_at=agent.last_heartbeat_at,
                connected=bool(
                    agent.last_heartbeat_at
                    and agent.last_heartbeat_at >= now - timedelta(seconds=45)
                ),
                cpu_percent=metric.cpu_percent if metric else None,
                memory_percent=metric.memory_percent if metric else None,
                disk_percent=metric.disk_percent if metric else None,
                disk_free_bytes=metric.disk_free_bytes if metric else None,
                uptime_seconds=metric.uptime_seconds if metric else None,
                package_count=int(package_count or 0),
            )
        )
    return result
