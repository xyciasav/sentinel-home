import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.incidents import record_monitor_transition
from sentinel.models import AuditEvent, ServiceMonitor, Session, User
from sentinel.monitoring import check_service

router = APIRouter(prefix="/api/v1/monitors", tags=["service monitors"])


class MonitorInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    group_name: str | None = Field(default=None, max_length=100)
    target_scope: str = Field(default="internal", pattern=r"^(internal|external)$")
    url: AnyHttpUrl
    device_id: uuid.UUID | None = None
    expected_status: int = Field(default=200, ge=100, le=599)
    expected_text: str | None = Field(default=None, max_length=500)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    verify_tls: bool = True
    enabled: bool = True
    severity: str = Field(default="normal", pattern=r"^(low|normal|high|critical)$")


class MonitorView(BaseModel):
    id: uuid.UUID
    name: str
    group_name: str | None
    target_scope: str
    url: str
    device_id: uuid.UUID | None
    expected_status: int
    expected_text: str | None
    timeout_seconds: int
    verify_tls: bool
    enabled: bool
    notifications_muted: bool
    severity: str
    status: str
    last_checked_at: datetime | None
    last_success_at: datetime | None
    outage_started_at: datetime | None
    last_response_ms: int | None
    last_status_code: int | None
    last_failure_reason: str | None


def monitor_view(item: ServiceMonitor) -> MonitorView:
    return MonitorView(**{field: getattr(item, field) for field in MonitorView.model_fields})


@router.get("", response_model=list[MonitorView])
async def list_monitors(
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[MonitorView]:
    items = await database.scalars(select(ServiceMonitor).order_by(ServiceMonitor.name))
    return [monitor_view(item) for item in items]


async def save_monitor(
    monitor: ServiceMonitor,
    payload: MonitorInput,
    database: AsyncSession,
    user: User,
    action: str,
) -> MonitorView:
    for field, value in payload.model_dump().items():
        if field == "url":
            value = str(value)
        elif field == "group_name" and value is not None:
            value = value.strip() or None
        setattr(monitor, field, value)
    database.add(monitor)
    await database.flush()
    if monitor.enabled:
        previous_status = monitor.status
        result = await check_service(monitor)
        database.add(result)
        await record_monitor_transition(database, monitor, previous_status, result.checked_at)
    else:
        monitor.status = "paused"
    database.add(
        AuditEvent(
            actor_user_id=user.id, action=action, target_type="monitor", target_id=str(monitor.id)
        )
    )
    await database.commit()
    return monitor_view(monitor)


@router.post("", response_model=MonitorView, status_code=201)
async def create_monitor(
    payload: MonitorInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> MonitorView:
    return await save_monitor(
        ServiceMonitor(), payload, database, authenticated[0], "monitor.create"
    )


@router.put("/{monitor_id}", response_model=MonitorView)
async def update_monitor(
    monitor_id: uuid.UUID,
    payload: MonitorInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> MonitorView:
    monitor = await database.get(ServiceMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "service monitor not found")
    return await save_monitor(monitor, payload, database, authenticated[0], "monitor.update")


@router.post("/{monitor_id}/check", response_model=MonitorView)
async def check_monitor_now(
    monitor_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> MonitorView:
    monitor = await database.get(ServiceMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "service monitor not found")
    previous_status = monitor.status
    result = await check_service(monitor)
    database.add(result)
    await record_monitor_transition(database, monitor, previous_status, result.checked_at)
    await database.commit()
    return monitor_view(monitor)


@router.delete("/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitor(
    monitor_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    monitor = await database.get(ServiceMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "service monitor not found")
    database.add(
        AuditEvent(
            actor_user_id=authenticated[0].id,
            action="monitor.delete",
            target_type="monitor",
            target_id=str(monitor.id),
        )
    )
    await database.delete(monitor)
    await database.commit()
