import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    AgentEnrollment,
    AgentMetric,
    AuditEvent,
    ContainerInstance,
    Device,
    InstalledPackage,
    RemediationPlan,
    Session,
    User,
    VulnerabilityFinding,
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
    source_name: str | None = Field(default=None, max_length=255)
    source_version: str | None = Field(default=None, max_length=255)


class ContainerInput(BaseModel):
    container_id: str = Field(pattern=r"^[a-f0-9]{12,64}$")
    name: str = Field(min_length=1, max_length=255)
    image: str = Field(min_length=1, max_length=500)
    state: str = Field(min_length=1, max_length=30)
    health: str | None = Field(default=None, max_length=30)
    status: str = Field(default="unknown", max_length=500)
    ports: str = Field(default="", max_length=1000)
    restart_count: int = Field(default=0, ge=0)


class HeartbeatInput(BaseModel):
    version: str = Field(min_length=1, max_length=40)
    executor_version: str | None = Field(default=None, max_length=40)
    cpu_percent: int = Field(ge=0, le=100)
    memory_percent: int = Field(ge=0, le=100)
    memory_used_bytes: int = Field(ge=0)
    memory_total_bytes: int = Field(ge=1)
    disk_percent: int = Field(ge=0, le=100)
    disk_free_bytes: int = Field(ge=0)
    disk_total_bytes: int = Field(ge=1)
    uptime_seconds: int = Field(ge=0)
    hostname: str | None = Field(default=None, max_length=255)
    os_name: str | None = Field(default=None, max_length=100)
    os_version: str | None = Field(default=None, max_length=100)
    kernel_version: str | None = Field(default=None, max_length=100)
    packages: list[PackageInput] | None = Field(default=None, max_length=20_000)
    containers: list[ContainerInput] | None = Field(default=None, max_length=2_000)


class AgentView(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    device_name: str
    version: str
    executor_version: str | None
    platform: str
    hostname: str | None
    os_name: str | None
    os_version: str | None
    kernel_version: str | None
    last_heartbeat_at: datetime | None
    connected: bool
    cpu_percent: int | None
    memory_percent: int | None
    disk_percent: int | None
    disk_free_bytes: int | None
    uptime_seconds: int | None
    package_count: int
    container_count: int


class MetricView(BaseModel):
    cpu_percent: int
    memory_percent: int
    disk_percent: int
    disk_free_bytes: int
    uptime_seconds: int
    collected_at: datetime


class PackageView(BaseModel):
    name: str
    version: str
    architecture: str | None
    manager: str
    source_name: str | None
    source_version: str | None
    observed_at: datetime


class CommandView(BaseModel):
    id: uuid.UUID
    operation: str
    package_name: str
    installed_version: str
    target_version: str
    signature: str


class CommandResultInput(BaseModel):
    status: str = Field(pattern=r"^(completed|failed)$")
    output: str = Field(default="", max_length=12_000)
    error: str | None = Field(default=None, max_length=500)


class CommandProgressInput(BaseModel):
    output: str = Field(max_length=12_000)


def command_payload(plan: RemediationPlan) -> dict[str, str]:
    return {
        "id": str(plan.id),
        "operation": plan.operation,
        "package_name": plan.package_name,
        "installed_version": plan.installed_version,
        "target_version": plan.target_version,
    }


def sign_command(plan: RemediationPlan, agent: Agent) -> str:
    body = json.dumps(command_payload(plan), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(bytes.fromhex(agent.credential_fingerprint), body, hashlib.sha256).hexdigest()


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
    if agent.last_heartbeat_at and agent.last_heartbeat_at > now - timedelta(seconds=2):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "heartbeat rate limit exceeded")
    agent.version = payload.version
    agent.executor_version = payload.executor_version
    agent.hostname = payload.hostname
    agent.os_name = payload.os_name
    agent.os_version = payload.os_version
    agent.kernel_version = payload.kernel_version
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
        current_sources: dict[str, set[str]] = {}
        for item in unique_packages.values():
            source_name = item.source_name or item.name
            source_version = item.source_version or item.version
            current_sources.setdefault(source_name, set()).add(source_version)
        active_package_findings = list(
            await database.scalars(
                select(VulnerabilityFinding).where(
                    VulnerabilityFinding.device_id == agent.device_id,
                    VulnerabilityFinding.detection_method == "osv-agent-package",
                    VulnerabilityFinding.status.in_(("open", "investigating")),
                )
            )
        )
        for finding in active_package_findings:
            versions = current_sources.get(finding.affected_package or "", set())
            if finding.installed_version not in versions:
                finding.status = "resolved"
    if payload.containers is not None:
        await database.execute(
            delete(ContainerInstance).where(ContainerInstance.agent_id == agent.id)
        )
        unique_containers = {item.container_id: item for item in payload.containers}
        database.add_all(
            ContainerInstance(agent_id=agent.id, observed_at=now, **item.model_dump())
            for item in unique_containers.values()
        )
    await database.commit()


@router.get("/commands/next", response_model=CommandView | None)
async def next_command(
    database: Annotated[AsyncSession, Depends(get_session)],
    agent: Annotated[Agent, Depends(authenticated_agent)],
) -> CommandView | None:
    if agent.executor_version != "0.3.2":
        return None
    retry_before = datetime.now(UTC) - timedelta(minutes=5)
    plan = await database.scalar(
        select(RemediationPlan)
        .where(
            RemediationPlan.agent_id == agent.id,
            or_(
                RemediationPlan.status == "queued",
                (RemediationPlan.status == "dispatched")
                & (RemediationPlan.dispatched_at < retry_before),
            ),
        )
        .order_by(RemediationPlan.approved_at, RemediationPlan.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if plan is None:
        return None
    plan.status = "dispatched"
    plan.dispatched_at = datetime.now(UTC)
    await database.commit()
    return CommandView(**command_payload(plan), signature=sign_command(plan, agent))


@router.post("/commands/{plan_id}/result", status_code=204)
async def command_result(
    plan_id: uuid.UUID,
    payload: CommandResultInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    agent: Annotated[Agent, Depends(authenticated_agent)],
) -> None:
    plan = await database.scalar(
        select(RemediationPlan)
        .where(RemediationPlan.id == plan_id, RemediationPlan.agent_id == agent.id)
        .with_for_update()
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation command not found")
    if plan.status != "dispatched":
        raise HTTPException(status.HTTP_409_CONFLICT, "remediation command is not dispatched")
    plan.status = payload.status
    plan.result_output = payload.output
    plan.result_error = payload.error
    plan.completed_at = datetime.now(UTC)
    if payload.status == "completed":
        finding = await database.get(VulnerabilityFinding, plan.finding_id)
        if finding is not None:
            finding.status = "resolved"
    await database.commit()


@router.put("/commands/{plan_id}/progress", status_code=204)
async def command_progress(
    plan_id: uuid.UUID,
    payload: CommandProgressInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    agent: Annotated[Agent, Depends(authenticated_agent)],
) -> None:
    plan = await database.scalar(
        select(RemediationPlan).where(
            RemediationPlan.id == plan_id,
            RemediationPlan.agent_id == agent.id,
            RemediationPlan.status == "dispatched",
        )
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "active remediation command not found")
    plan.result_output = payload.output
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
        container_count = await database.scalar(
            select(func.count(ContainerInstance.id)).where(ContainerInstance.agent_id == agent.id)
        )
        result.append(
            AgentView(
                id=agent.id,
                device_id=device.id,
                device_name=device.display_name,
                version=agent.version,
                executor_version=agent.executor_version,
                platform=agent.platform,
                hostname=agent.hostname,
                os_name=agent.os_name,
                os_version=agent.os_version,
                kernel_version=agent.kernel_version,
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
                container_count=int(container_count or 0),
            )
        )
    return result


@router.get("/{agent_id}/metrics", response_model=list[MetricView])
async def agent_metrics(
    agent_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 240,
) -> list[AgentMetric]:
    if await database.get(Agent, agent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    items = list(
        await database.scalars(
            select(AgentMetric)
            .where(AgentMetric.agent_id == agent_id)
            .order_by(AgentMetric.collected_at.desc())
            .limit(limit)
        )
    )
    return list(reversed(items))


@router.get("/{agent_id}/packages", response_model=list[PackageView])
async def agent_packages(
    agent_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
    search: Annotated[str | None, Query(max_length=100)] = None,
) -> list[InstalledPackage]:
    if await database.get(Agent, agent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    query = select(InstalledPackage).where(InstalledPackage.agent_id == agent_id)
    if search:
        query = query.where(InstalledPackage.name.ilike(f"%{search}%"))
    return list(await database.scalars(query.order_by(InstalledPackage.name).limit(500)))


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    agent = await database.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="agent.delete",
            target_type="agent",
            target_id=str(agent.id),
        )
    )
    await database.delete(agent)
    await database.commit()
