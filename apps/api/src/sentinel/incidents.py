import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import Incident, IncidentEvent, ServiceMonitor, Session, User

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class EventView(BaseModel):
    kind: str
    message: str
    occurred_at: datetime


class IncidentView(BaseModel):
    id: uuid.UUID
    monitor_id: uuid.UUID
    title: str
    severity: str
    status: str
    summary: str
    started_at: datetime
    recovered_at: datetime | None
    acknowledged_at: datetime | None
    events: list[EventView]


def incident_view(item: Incident) -> IncidentView:
    return IncidentView(
        **{field: getattr(item, field) for field in IncidentView.model_fields if field != "events"},
        events=[EventView.model_validate(event, from_attributes=True) for event in item.events],
    )


async def record_monitor_transition(
    database: AsyncSession, monitor: ServiceMonitor, previous_status: str, checked_at: datetime
) -> None:
    active = await database.scalar(
        select(Incident)
        .where(Incident.monitor_id == monitor.id, Incident.status == "open")
        .options(selectinload(Incident.events))
    )
    if monitor.status == "down" and previous_status != "down" and active is None:
        reason = monitor.last_failure_reason or "service check failed"
        incident = Incident(
            monitor_id=monitor.id,
            device_id=monitor.device_id,
            title=f"{monitor.name} is unavailable",
            severity=monitor.severity,
            summary=reason,
            started_at=checked_at,
            events=[IncidentEvent(kind="outage", message=reason, occurred_at=checked_at)],
        )
        database.add(incident)
    elif monitor.status == "up" and active is not None:
        active.status = "recovered"
        active.recovered_at = checked_at
        active.summary = "Service recovered after a failed availability check."
        active.events.append(
            IncidentEvent(
                kind="recovery",
                message=f"Service responded successfully in {monitor.last_response_ms or 0} ms.",
                occurred_at=checked_at,
            )
        )


@router.get("", response_model=list[IncidentView])
async def list_incidents(
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[IncidentView]:
    items = await database.scalars(
        select(Incident).options(selectinload(Incident.events)).order_by(Incident.started_at.desc())
    )
    return [incident_view(item) for item in items]


@router.post("/{incident_id}/acknowledge", response_model=IncidentView)
async def acknowledge_incident(
    incident_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> IncidentView:
    incident = await database.scalar(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.events))
    )
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    if incident.acknowledged_at is None:
        incident.acknowledged_at = datetime.now(UTC)
        incident.acknowledged_by = authenticated[0].id
        incident.events.append(
            IncidentEvent(
                kind="acknowledgment",
                message=f"Acknowledged by {authenticated[0].username}.",
                occurred_at=incident.acknowledged_at,
            )
        )
        await database.commit()
    return incident_view(incident)
