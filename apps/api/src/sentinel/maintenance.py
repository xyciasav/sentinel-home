import uuid
from datetime import datetime
from typing import Annotated
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import AuditEvent, MaintenanceWindow, ServiceMonitor, Session, User

router = APIRouter(prefix="/api/v1/maintenance", tags=["maintenance"])


class MaintenanceInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    device_id: uuid.UUID | None = None
    monitor_id: uuid.UUID | None = None
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    time_of_day: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    duration_minutes: int = Field(ge=5, le=1440)
    timezone: str = Field(min_length=1, max_length=100)
    suppress_notifications: bool = True
    enabled: bool = True

    @model_validator(mode="after")
    def validate_scope_and_timezone(self) -> "MaintenanceInput":
        if not self.device_id and not self.monitor_id:
            raise ValueError("select a device or service")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("unknown IANA timezone") from error
        return self


class MaintenanceView(MaintenanceInput):
    id: uuid.UUID
    active: bool
    created_at: datetime


def window_active(window: MaintenanceWindow, at: datetime) -> bool:
    local = at.astimezone(ZoneInfo(window.timezone))
    hour, minute = (int(value) for value in window.time_of_day.split(":"))
    current_minute = local.weekday() * 1440 + local.hour * 60 + local.minute
    start_minute = (
        (window.day_of_week if window.day_of_week is not None else local.weekday()) * 1440
        + hour * 60
        + minute
    )
    if window.day_of_week is None:
        elapsed = (local.hour * 60 + local.minute - (hour * 60 + minute)) % 1440
    else:
        elapsed = (current_minute - start_minute) % (7 * 1440)
    return window.enabled and elapsed < window.duration_minutes


async def active_maintenance(
    database: AsyncSession, monitor: ServiceMonitor, at: datetime
) -> MaintenanceWindow | None:
    windows = list(
        await database.scalars(
            select(MaintenanceWindow).where(
                MaintenanceWindow.enabled.is_(True),
                or_(
                    MaintenanceWindow.monitor_id == monitor.id,
                    MaintenanceWindow.device_id == monitor.device_id,
                ),
            )
        )
    )
    return next((window for window in windows if window_active(window, at)), None)


def maintenance_view(window: MaintenanceWindow) -> MaintenanceView:
    return MaintenanceView(
        **{field: getattr(window, field) for field in MaintenanceInput.model_fields},
        id=window.id,
        active=window_active(window, datetime.now().astimezone()),
        created_at=window.created_at,
    )


@router.get("", response_model=list[MaintenanceView])
async def list_windows(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[MaintenanceView]:
    windows = list(
        await database.scalars(select(MaintenanceWindow).order_by(MaintenanceWindow.name))
    )
    return [maintenance_view(window) for window in windows]


@router.post("", response_model=MaintenanceView, status_code=201)
async def create_window(
    payload: MaintenanceInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> MaintenanceView:
    window = MaintenanceWindow(**payload.model_dump(), created_by=auth[0].id)
    database.add(window)
    await database.flush()
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="maintenance.create",
            target_type="maintenance_window",
            target_id=str(window.id),
        )
    )
    await database.commit()
    return maintenance_view(window)


@router.delete("/{window_id}", status_code=204)
async def delete_window(
    window_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    window = await database.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "maintenance window not found")
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="maintenance.delete",
            target_type="maintenance_window",
            target_id=str(window.id),
        )
    )
    await database.delete(window)
    await database.commit()
