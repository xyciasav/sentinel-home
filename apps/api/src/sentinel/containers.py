import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    AuditEvent,
    ContainerEvent,
    ContainerInstance,
    Device,
    Session,
    User,
)

router = APIRouter(prefix="/api/v1/containers", tags=["containers"])


class ContainerView(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    device_id: uuid.UUID
    device_name: str
    hostname: str | None
    container_id: str
    name: str
    image: str
    state: str
    health: str | None
    status: str | None
    ports: str | None
    restart_count: int
    present: bool
    observed_at: datetime
    stale: bool


@router.get("", response_model=list[ContainerView])
async def list_containers(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
    search: Annotated[str | None, Query(max_length=100)] = None,
) -> list[ContainerView]:
    query = (
        select(ContainerInstance, Agent, Device)
        .join(Agent, Agent.id == ContainerInstance.agent_id)
        .join(Device, Device.id == Agent.device_id)
        .where(Agent.revoked_at.is_(None))
    )
    if search:
        term = f"%{search}%"
        query = query.where(
            or_(ContainerInstance.name.ilike(term), ContainerInstance.image.ilike(term))
        )
    rows = (
        await database.execute(query.order_by(Device.display_name, ContainerInstance.name))
    ).all()
    stale_before = datetime.now(UTC) - timedelta(minutes=10)
    return [
        ContainerView(
            id=container.id,
            agent_id=agent.id,
            device_id=device.id,
            device_name=device.display_name,
            hostname=agent.hostname,
            container_id=container.container_id,
            name=container.name,
            image=container.image,
            state=container.state,
            health=container.health,
            status=container.status,
            ports=container.ports,
            restart_count=container.restart_count,
            present=container.present,
            observed_at=container.observed_at,
            stale=container.observed_at < stale_before,
        )
        for container, agent, device in rows
    ]


class ContainerEventView(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    device_name: str
    container_id: str
    container_name: str
    kind: str
    severity: str
    message: str
    acknowledged_at: datetime | None
    occurred_at: datetime


class BulkAcknowledgeRequest(BaseModel):
    ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


@router.get("/events", response_model=list[ContainerEventView])
async def list_container_events(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[ContainerEventView]:
    rows = (
        await database.execute(
            select(ContainerEvent, Device.display_name)
            .join(Agent, Agent.id == ContainerEvent.agent_id)
            .join(Device, Device.id == Agent.device_id)
            .order_by(ContainerEvent.occurred_at.desc())
            .limit(500)
        )
    ).all()
    return [
        ContainerEventView(
            **{
                field: getattr(event, field)
                for field in ContainerEventView.model_fields
                if field != "device_name"
            },
            device_name=device_name,
        )
        for event, device_name in rows
    ]


@router.post("/events/{event_id}/acknowledge", response_model=ContainerEventView)
async def acknowledge_container_event(
    event_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> ContainerEventView:
    row = (
        await database.execute(
            select(ContainerEvent, Device.display_name)
            .join(Agent, Agent.id == ContainerEvent.agent_id)
            .join(Device, Device.id == Agent.device_id)
            .where(ContainerEvent.id == event_id)
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "container event not found")
    event, device_name = row
    if event.acknowledged_at is None:
        event.acknowledged_at = datetime.now(UTC)
        event.acknowledged_by = auth[0].id
        database.add(
            AuditEvent(
                actor_user_id=auth[0].id,
                action="container.event.acknowledge",
                target_type="container_event",
                target_id=str(event.id),
            )
        )
        await database.commit()
    return ContainerEventView(
        **{
            field: getattr(event, field)
            for field in ContainerEventView.model_fields
            if field != "device_name"
        },
        device_name=device_name,
    )


@router.post("/bulk/events/acknowledge", status_code=204)
async def acknowledge_container_events(
    payload: BulkAcknowledgeRequest,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    events = list(
        await database.scalars(
            select(ContainerEvent).where(
                ContainerEvent.id.in_(payload.ids),
                ContainerEvent.acknowledged_at.is_(None),
            )
        )
    )
    acknowledged_at = datetime.now(UTC)
    for event in events:
        event.acknowledged_at = acknowledged_at
        event.acknowledged_by = auth[0].id
        database.add(
            AuditEvent(
                actor_user_id=auth[0].id,
                action="container.event.acknowledge.bulk",
                target_type="container_event",
                target_id=str(event.id),
            )
        )
    await database.commit()
