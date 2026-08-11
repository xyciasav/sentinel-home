import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session
from sentinel.database import get_session
from sentinel.models import Agent, ContainerInstance, Device, Session, User

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
            observed_at=container.observed_at,
            stale=container.observed_at < stale_before,
        )
        for container, agent, device in rows
    ]
