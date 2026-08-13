import uuid
from datetime import UTC, datetime
from difflib import SequenceMatcher
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    AgentEnrollment,
    AgentMetric,
    AuditEvent,
    ContainerInstance,
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


class HostAgentSummary(BaseModel):
    connected: bool
    version: str
    cpu_percent: int | None
    memory_percent: int | None
    disk_percent: int | None
    uptime_seconds: int | None
    scan_status: str
    last_scan_at: datetime | None
    next_scan_at: datetime | None
    scan_error: str | None


class HostServiceSummary(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    url: str
    response_ms: int | None


class HostContainerSummary(BaseModel):
    id: uuid.UUID
    name: str
    image: str
    state: str
    health: str | None
    restart_count: int


class HostChangeSummary(BaseModel):
    kind: str
    port: int
    service: str | None
    detected_at: datetime


class HostDetailView(BaseModel):
    device: DeviceView
    agent: HostAgentSummary | None
    services: list[HostServiceSummary]
    containers: list[HostContainerSummary]
    actionable_vulnerabilities: int
    informational_vulnerabilities: int
    critical_high: int
    known_exploited: int
    recent_changes: list[HostChangeSummary]


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


@router.get("/{device_id}/overview", response_model=HostDetailView)
async def device_overview(
    device_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> HostDetailView:
    device = await database.scalar(
        select(Device).where(Device.id == device_id).options(selectinload(Device.addresses))
    )
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    now = datetime.now(UTC)
    agent = await database.scalar(
        select(Agent).where(Agent.device_id == device.id, Agent.revoked_at.is_(None))
    )
    metric = (
        await database.scalar(
            select(AgentMetric)
            .where(AgentMetric.agent_id == agent.id)
            .order_by(AgentMetric.collected_at.desc())
            .limit(1)
        )
        if agent
        else None
    )
    services = list(
        await database.scalars(
            select(ServiceMonitor)
            .where(ServiceMonitor.device_id == device.id)
            .order_by(ServiceMonitor.name)
        )
    )
    containers = (
        list(
            await database.scalars(
                select(ContainerInstance)
                .where(ContainerInstance.agent_id == agent.id, ContainerInstance.present.is_(True))
                .order_by(ContainerInstance.name)
            )
        )
        if agent
        else []
    )
    active = (
        VulnerabilityFinding.device_id == device.id,
        VulnerabilityFinding.status.in_(("open", "investigating")),
    )
    actionable = or_(
        VulnerabilityFinding.severity != "unknown",
        VulnerabilityFinding.known_exploited.is_(True),
    )
    count = lambda *filters: database.scalar(  # noqa: E731
        select(func.count(VulnerabilityFinding.id)).where(*filters)
    )
    return HostDetailView(
        device=device_view(device),
        agent=(
            HostAgentSummary(
                connected=bool(
                    agent.last_heartbeat_at
                    and (now - agent.last_heartbeat_at).total_seconds() <= 45
                ),
                version=agent.version,
                cpu_percent=metric.cpu_percent if metric else None,
                memory_percent=metric.memory_percent if metric else None,
                disk_percent=metric.disk_percent if metric else None,
                uptime_seconds=metric.uptime_seconds if metric else None,
                scan_status=agent.vulnerability_scan_status,
                last_scan_at=agent.last_vulnerability_scan_at,
                next_scan_at=agent.next_vulnerability_scan_at,
                scan_error=agent.vulnerability_scan_error,
            )
            if agent
            else None
        ),
        services=[
            HostServiceSummary(
                id=item.id,
                name=item.name,
                status=item.status,
                url=item.url,
                response_ms=item.last_response_ms,
            )
            for item in services
        ],
        containers=[
            HostContainerSummary(
                id=item.id,
                name=item.name,
                image=item.image,
                state=item.state,
                health=item.health,
                restart_count=item.restart_count,
            )
            for item in containers
        ],
        actionable_vulnerabilities=int(await count(*active, actionable) or 0),
        informational_vulnerabilities=int(
            await count(
                *active,
                VulnerabilityFinding.severity == "unknown",
                VulnerabilityFinding.known_exploited.is_(False),
            )
            or 0
        ),
        critical_high=int(
            await count(*active, VulnerabilityFinding.severity.in_(("critical", "high"))) or 0
        ),
        known_exploited=int(
            await count(*active, VulnerabilityFinding.known_exploited.is_(True)) or 0
        ),
        recent_changes=[
            HostChangeSummary.model_validate(item, from_attributes=True)
            for item in await database.scalars(
                select(NetworkChange)
                .where(NetworkChange.device_id == device.id)
                .order_by(NetworkChange.detected_at.desc())
                .limit(20)
            )
        ],
    )


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
