import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import AuditEvent, Device, DeviceAddress, DeviceTrust, Session, User
from sentinel.monitoring import check_device

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


class DeviceCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    address: str = Field(min_length=1, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    device_type: str | None = Field(default=None, max_length=50)
    criticality: str = Field(default="normal", pattern=r"^(low|normal|high|critical)$")
    trust: DeviceTrust = DeviceTrust.trusted
    monitor_port: int | None = Field(default=443, ge=1, le=65535)
    notes: str | None = Field(default=None, max_length=4000)


class DeviceView(BaseModel):
    id: uuid.UUID
    display_name: str
    address: str
    hostname: str | None
    device_type: str | None
    criticality: str
    trust: DeviceTrust
    monitor_port: int | None
    status: str
    last_checked_at: datetime | None
    last_latency_ms: int | None
    last_failure_reason: str | None


def device_view(device: Device) -> DeviceView:
    return DeviceView(
        id=device.id,
        display_name=device.display_name,
        address=device.addresses[0].address if device.addresses else "",
        hostname=device.hostname,
        device_type=device.device_type,
        criticality=device.criticality,
        trust=device.trust,
        monitor_port=device.monitor_port,
        status=device.status,
        last_checked_at=device.last_checked_at,
        last_latency_ms=device.last_latency_ms,
        last_failure_reason=device.last_failure_reason,
    )


@router.get("", response_model=list[DeviceView])
async def list_devices(
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[DeviceView]:
    devices = await database.scalars(
        select(Device).options(selectinload(Device.addresses)).order_by(Device.display_name)
    )
    return [device_view(device) for device in devices]


@router.post("", response_model=DeviceView, status_code=201)
async def create_device(
    payload: DeviceCreate,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> DeviceView:
    user, _ = authenticated
    existing = await database.scalar(
        select(DeviceAddress).where(DeviceAddress.address == payload.address)
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a device already uses this address")
    device = Device(
        display_name=payload.display_name.strip(),
        hostname=payload.hostname,
        device_type=payload.device_type,
        criticality=payload.criticality,
        trust=payload.trust,
        monitor_port=payload.monitor_port,
        notes=payload.notes,
        addresses=[DeviceAddress(address=payload.address.strip(), kind="host")],
    )
    database.add(device)
    await database.flush()
    await check_device(device)
    database.add(
        AuditEvent(
            actor_user_id=user.id,
            action="device.create",
            target_type="device",
            target_id=str(device.id),
        )
    )
    await database.commit()
    return device_view(device)


@router.post("/{device_id}/check", response_model=DeviceView)
async def check_device_now(
    device_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> DeviceView:
    device = await database.scalar(
        select(Device).where(Device.id == device_id).options(selectinload(Device.addresses))
    )
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    await check_device(device)
    await database.commit()
    return device_view(device)
