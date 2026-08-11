import uuid
from datetime import datetime
from difflib import SequenceMatcher
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    AgentEnrollment,
    AuditEvent,
    Device,
    DeviceAddress,
    DeviceTrust,
    DiscoveredHost,
    Incident,
    MaintenanceWindow,
    NetworkChange,
    ServiceMonitor,
    Session,
    SourceDevice,
    User,
    VulnerabilityFinding,
)
from sentinel.monitoring import check_device

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


class DeviceCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    agent_applicable: bool = True
    address: str = Field(min_length=1, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    device_type: str | None = Field(default=None, max_length=50)
    criticality: str = Field(default="normal", pattern=r"^(low|normal|high|critical)$")
    trust: DeviceTrust = DeviceTrust.trusted
    monitor_port: int | None = Field(default=443, ge=1, le=65535)
    notes: str | None = Field(default=None, max_length=4000)


class DeviceView(BaseModel):
    id: uuid.UUID
    agent_applicable: bool
    mac_address: str | None
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
    notes: str | None
    alerts_muted_until: datetime | None
    alert_mute_reason: str | None
    notifications_muted: bool


def device_view(device: Device) -> DeviceView:
    return DeviceView(
        id=device.id,
        agent_applicable=device.agent_applicable,
        mac_address=device.mac_address,
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
        notes=device.notes,
        alerts_muted_until=device.alerts_muted_until,
        alert_mute_reason=device.alert_mute_reason,
        notifications_muted=device.notifications_muted,
    )


class DuplicateCandidate(BaseModel):
    left: DeviceView
    right: DeviceView
    confidence: int
    reasons: list[str]


class MergeInput(BaseModel):
    source_id: uuid.UUID


def duplicate_evidence(left: Device, right: Device) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    left_addresses = {item.address.lower() for item in left.addresses}
    right_addresses = {item.address.lower() for item in right.addresses}
    if left_addresses & right_addresses:
        score += 100
        reasons.append("Same network address")
    if left.mac_address and left.mac_address == right.mac_address:
        score += 100
        reasons.append("Same MAC address")
    if left.hostname and right.hostname and left.hostname.lower() == right.hostname.lower():
        score += 80
        reasons.append("Same hostname")
    similarity = SequenceMatcher(
        None, left.display_name.lower(), right.display_name.lower()
    ).ratio()
    if similarity >= 0.88:
        score += 45
        reasons.append("Very similar names")
    return min(score, 100), reasons


@router.get("/duplicate-candidates", response_model=list[DuplicateCandidate])
async def duplicate_candidates(
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[DuplicateCandidate]:
    devices = list(
        await database.scalars(
            select(Device).options(selectinload(Device.addresses)).order_by(Device.display_name)
        )
    )
    candidates = []
    for index, left in enumerate(devices):
        for right in devices[index + 1 :]:
            confidence, reasons = duplicate_evidence(left, right)
            if confidence >= 45:
                candidates.append(
                    DuplicateCandidate(
                        left=device_view(left),
                        right=device_view(right),
                        confidence=confidence,
                        reasons=reasons,
                    )
                )
    return sorted(candidates, key=lambda item: item.confidence, reverse=True)


@router.post("/{target_id}/merge", response_model=DeviceView)
async def merge_device(
    target_id: uuid.UUID,
    payload: MergeInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> DeviceView:
    if target_id == payload.source_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "select two different devices")
    target = await database.scalar(
        select(Device).where(Device.id == target_id).options(selectinload(Device.addresses))
    )
    source = await database.scalar(
        select(Device).where(Device.id == payload.source_id).options(selectinload(Device.addresses))
    )
    if target is None or source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    target_agent = await database.scalar(select(Agent.id).where(Agent.device_id == target.id))
    source_agent = await database.scalar(select(Agent.id).where(Agent.device_id == source.id))
    if target_agent and source_agent:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "both devices have agents; remove or re-enroll one agent before merging",
        )
    target_addresses = {item.address.lower() for item in target.addresses}
    for address in list(source.addresses):
        if address.address.lower() not in target_addresses:
            target.addresses.append(address)
            target_addresses.add(address.address.lower())
        else:
            source.addresses.remove(address)
            await database.delete(address)
    for model in (
        ServiceMonitor,
        Incident,
        MaintenanceWindow,
        DiscoveredHost,
        NetworkChange,
        VulnerabilityFinding,
        AgentEnrollment,
    ):
        await database.execute(
            update(model).where(model.device_id == source.id).values(device_id=target.id)
        )
    await database.execute(
        update(SourceDevice)
        .where(SourceDevice.imported_device_id == source.id)
        .values(imported_device_id=target.id)
    )
    if source_agent:
        await database.execute(
            update(Agent).where(Agent.device_id == source.id).values(device_id=target.id)
        )
    target.hostname = target.hostname or source.hostname
    target.mac_address = target.mac_address or source.mac_address
    target.device_type = target.device_type or source.device_type
    target.notes = target.notes or source.notes
    target.notifications_muted = target.notifications_muted or source.notifications_muted
    database.add(
        AuditEvent(
            actor_user_id=authenticated[0].id,
            action="device.merge",
            target_type="device",
            target_id=str(target.id),
        )
    )
    await database.delete(source)
    await database.commit()
    await database.refresh(target, attribute_names=["addresses"])
    return device_view(target)


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
        agent_applicable=payload.agent_applicable,
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


@router.put("/{device_id}", response_model=DeviceView)
async def update_device(
    device_id: uuid.UUID,
    payload: DeviceCreate,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> DeviceView:
    user, _ = authenticated
    device = await database.scalar(
        select(Device).where(Device.id == device_id).options(selectinload(Device.addresses))
    )
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    duplicate = await database.scalar(
        select(DeviceAddress).where(
            DeviceAddress.address == payload.address,
            DeviceAddress.device_id != device.id,
        )
    )
    if duplicate is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a device already uses this address")
    device.display_name = payload.display_name.strip()
    device.agent_applicable = payload.agent_applicable
    device.hostname = payload.hostname
    device.device_type = payload.device_type
    device.criticality = payload.criticality
    device.trust = payload.trust
    device.monitor_port = payload.monitor_port
    device.notes = payload.notes
    if device.addresses:
        device.addresses[0].address = payload.address.strip()
    else:
        device.addresses.append(DeviceAddress(address=payload.address.strip(), kind="host"))
    await check_device(device)
    database.add(
        AuditEvent(
            actor_user_id=user.id,
            action="device.update",
            target_type="device",
            target_id=str(device.id),
        )
    )
    await database.commit()
    return device_view(device)
