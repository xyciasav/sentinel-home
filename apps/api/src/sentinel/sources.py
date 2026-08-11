import asyncio
import ipaddress
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.config import get_settings
from sentinel.database import get_session, get_session_factory
from sentinel.models import (
    AuditEvent,
    Device,
    DeviceAddress,
    DeviceTrust,
    InventorySource,
    NetworkIdentityEvent,
    Session,
    SourceDevice,
    User,
)
from sentinel.security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/v1/sources", tags=["inventory sources"])
logger = logging.getLogger(__name__)


class SourceInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str = Field(default="home_assistant", pattern=r"^(home_assistant|pihole)$")
    base_url: AnyHttpUrl
    token: str = Field(min_length=1, max_length=1000)


class SourceView(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    base_url: str
    enabled: bool
    last_sync_at: datetime | None
    last_sync_status: str
    last_sync_error: str | None
    device_count: int
    importable_count: int
    imported_count: int
    summary: dict | None


class SourceDeviceView(BaseModel):
    id: uuid.UUID
    external_id: str
    name: str
    address: str | None
    mac_address: str | None
    manufacturer: str | None
    model: str | None
    area_name: str | None
    imported_device_id: uuid.UUID | None


class ImportInput(BaseModel):
    ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class NetworkAssetView(BaseModel):
    id: str
    name: str
    address: str | None
    mac_address: str | None
    status: str
    sources: list[str]
    observations: int
    linked: bool
    last_seen_at: datetime | None
    observation_ids: list[uuid.UUID]


class LinkNetworkIdentityInput(BaseModel):
    observation_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)
    device_id: uuid.UUID | None = None


class NetworkIdentityEventView(BaseModel):
    id: uuid.UUID
    kind: str
    name: str
    source_name: str
    old_value: str | None
    new_value: str | None
    occurred_at: datetime


def safe_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid Home Assistant URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        allowed = address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        allowed = (
            parsed.hostname == "pi.hole"
            or parsed.hostname.endswith(".local")
            or "." not in parsed.hostname
        )
    if not allowed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Home Assistant must use a private IP or local hostname",
        )
    return value.rstrip("/")


def websocket_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(
        ("wss" if parsed.scheme == "https" else "ws", parsed.netloc, "/api/websocket", "", "", "")
    )


def pihole_api_base(base_url: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")


async def ws_command(socket, command_id: int, command_type: str) -> list[dict]:
    await socket.send(json.dumps({"id": command_id, "type": command_type}))
    response = json.loads(await socket.recv())
    if not response.get("success"):
        raise RuntimeError(str(response.get("error", {}).get("message") or command_type))
    return response.get("result") or []


async def fetch_home_assistant(source: InventorySource) -> list[dict]:
    token = decrypt_secret(source.credential_encrypted)
    async with connect(
        websocket_url(source.base_url), open_timeout=10, close_timeout=5, proxy=None
    ) as socket:
        hello = json.loads(await socket.recv())
        if hello.get("type") != "auth_required":
            raise RuntimeError("unexpected Home Assistant authentication response")
        await socket.send(json.dumps({"type": "auth", "access_token": token}))
        authenticated = json.loads(await socket.recv())
        if authenticated.get("type") != "auth_ok":
            raise RuntimeError("Home Assistant rejected the access token")
        devices = await ws_command(socket, 1, "config/device_registry/list")
        entities = await ws_command(socket, 2, "config/entity_registry/list")
        areas = await ws_command(socket, 3, "config/area_registry/list")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=15, trust_env=False, follow_redirects=False) as client:
        response = await client.get(f"{source.base_url}/api/states", headers=headers)
        response.raise_for_status()
        states = response.json()
    state_by_entity = {item.get("entity_id"): item for item in states if item.get("entity_id")}
    area_names = {item.get("area_id"): item.get("name") for item in areas}
    entities_by_device: dict[str, list[dict]] = {}
    for entity in entities:
        if entity.get("device_id"):
            entities_by_device.setdefault(entity["device_id"], []).append(entity)
    result = []
    for device in devices:
        attributes = []
        for entity in entities_by_device.get(device.get("id"), []):
            state = state_by_entity.get(entity.get("entity_id"), {})
            attributes.append(state.get("attributes") or {})
        address = next(
            (
                value
                for attrs in attributes
                for value in (attrs.get("ip"), attrs.get("ip_address"))
                if value and _private_address(str(value))
            ),
            None,
        )
        mac = next(
            (str(value) for kind, value in device.get("connections", []) if kind == "mac"), None
        )
        name = (
            device.get("name_by_user")
            or device.get("name")
            or device.get("model")
            or "Unnamed device"
        )
        result.append(
            {
                "external_id": str(device["id"]),
                "name": str(name)[:255],
                "address": str(address)[:45] if address else None,
                "mac_address": mac[:30] if mac else None,
                "manufacturer": str(device.get("manufacturer"))[:100]
                if device.get("manufacturer")
                else None,
                "model": str(device.get("model"))[:100] if device.get("model") else None,
                "area_name": area_names.get(device.get("area_id")),
            }
        )
    return result


async def fetch_pihole(source: InventorySource) -> tuple[list[dict], dict]:
    credential = decrypt_secret(source.credential_encrypted)
    base_url = pihole_api_base(source.base_url)
    try:
        return await fetch_pihole_v6(base_url, credential)
    except (httpx.HTTPError, RuntimeError, ValueError) as v6_error:
        try:
            return await fetch_pihole_v5(base_url, credential)
        except (httpx.HTTPError, RuntimeError, ValueError) as legacy_error:
            raise RuntimeError(
                "Pi-hole authentication failed for both the v6 application-password API "
                f"and legacy API token ({legacy_error})"
            ) from v6_error


async def fetch_pihole_v6(base_url: str, password: str) -> tuple[list[dict], dict]:
    async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as client:
        authentication = await client.post(f"{base_url}/api/auth", json={"password": password})
        authentication.raise_for_status()
        try:
            session = authentication.json().get("session") or {}
        except ValueError as error:
            raise RuntimeError(
                "Pi-hole did not return API data. Use its server URL, not /admin/login.php."
            ) from error
        sid = session.get("sid")
        if not session.get("valid") or not sid:
            raise RuntimeError("Pi-hole rejected the application password")
        headers = {"X-FTL-SID": sid, "Accept": "application/json"}
        devices_response, summary_response, blocking_response = await asyncio.gather(
            client.get(
                f"{base_url}/api/network/devices",
                headers=headers,
                params={"max_devices": 1000, "max_addresses": 10},
            ),
            client.get(f"{base_url}/api/stats/summary", headers=headers),
            client.get(f"{base_url}/api/dns/blocking", headers=headers),
        )
        for response in (devices_response, summary_response, blocking_response):
            response.raise_for_status()
        await client.delete(f"{base_url}/api/auth", headers=headers)
    raw_summary = summary_response.json()
    summary = {
        "blocking": bool(blocking_response.json().get("blocking")),
        "queries": raw_summary.get("queries") or {},
        "clients": raw_summary.get("clients") or {},
        "gravity": raw_summary.get("gravity") or {},
    }
    return parse_pihole_devices(devices_response.json().get("devices", [])), summary


async def fetch_pihole_v5(base_url: str, token: str) -> tuple[list[dict], dict]:
    async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as client:
        summary_response, clients_response = await asyncio.gather(
            client.get(
                f"{base_url}/admin/api.php",
                params={"summaryRaw": "", "auth": token},
            ),
            client.get(
                f"{base_url}/admin/api.php",
                params={"getQuerySources": "", "auth": token},
            ),
        )
        for response in (summary_response, clients_response):
            response.raise_for_status()
    try:
        raw_summary = summary_response.json()
        raw_clients = clients_response.json()
    except ValueError as error:
        raise RuntimeError("legacy Pi-hole API token returned a non-JSON response") from error
    if not isinstance(raw_summary, dict) or "status" not in raw_summary:
        raise RuntimeError("legacy Pi-hole API token was rejected")
    top_sources = raw_clients.get("top_sources", raw_clients)
    devices = []
    if isinstance(top_sources, dict):
        for identity in top_sources:
            parts = str(identity).split("|")
            address = next((part for part in parts if _private_address(part)), None)
            if not address:
                continue
            hostname = next((part for part in parts if part != address and part), None)
            devices.append(
                {
                    "external_id": address,
                    "name": (hostname or address)[:255],
                    "address": address[:45],
                    "mac_address": None,
                    "manufacturer": None,
                    "model": "Pi-hole DNS client",
                    "area_name": "Pi-hole v5 API",
                }
            )
    summary = {
        "blocking": raw_summary.get("status") == "enabled",
        "queries": {
            "total": raw_summary.get("dns_queries_today", 0),
            "blocked": raw_summary.get("ads_blocked_today", 0),
            "percent_blocked": raw_summary.get("ads_percentage_today", 0),
        },
        "clients": {
            "active": raw_summary.get("unique_clients", 0),
            "total": raw_summary.get("clients_ever_seen", 0),
        },
        "gravity": {"domains_being_blocked": raw_summary.get("domains_being_blocked", 0)},
    }
    return devices, summary


def parse_pihole_devices(devices: list[dict]) -> list[dict]:
    result = []
    for device in devices:
        addresses = sorted(
            device.get("ips") or [], key=lambda value: value.get("lastSeen") or 0, reverse=True
        )
        selected = next(
            (value for value in addresses if _private_address(str(value.get("ip") or ""))),
            None,
        )
        address = str(selected.get("ip")) if selected else None
        hostname = str(selected.get("name")) if selected and selected.get("name") else None
        mac = str(device.get("hwaddr") or "") or None
        external_id = str(device.get("id") or mac or address or "")
        if not external_id:
            continue
        result.append(
            {
                "external_id": external_id[:255],
                "name": (hostname or mac or address or "Unnamed Pi-hole client")[:255],
                "address": address[:45] if address else None,
                "mac_address": mac[:30] if mac else None,
                "manufacturer": str(device.get("macVendor"))[:100]
                if device.get("macVendor")
                else None,
                "model": str(device.get("interface"))[:100] if device.get("interface") else None,
                "area_name": "Pi-hole DNS client",
            }
        )
    return result


def _private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return False


async def source_view(database: AsyncSession, source: InventorySource) -> SourceView:
    devices = list(
        await database.scalars(select(SourceDevice).where(SourceDevice.source_id == source.id))
    )
    return SourceView(
        id=source.id,
        name=source.name,
        kind=source.kind,
        base_url=source.base_url,
        enabled=source.enabled,
        last_sync_at=source.last_sync_at,
        last_sync_status=source.last_sync_status,
        last_sync_error=source.last_sync_error,
        device_count=len(devices),
        importable_count=sum(not item.imported_device_id for item in devices),
        imported_count=sum(bool(item.imported_device_id) for item in devices),
        summary=json.loads(source.summary_json) if source.summary_json else None,
    )


async def synchronize_source(database: AsyncSession, source: InventorySource) -> None:
    try:
        if source.kind == "pihole":
            source.base_url = pihole_api_base(source.base_url)
            incoming, summary = await fetch_pihole(source)
            source.summary_json = json.dumps(summary)
        else:
            incoming = await fetch_home_assistant(source)
        existing = {
            item.external_id: item
            for item in await database.scalars(
                select(SourceDevice).where(SourceDevice.source_id == source.id)
            )
        }
        now = datetime.now(UTC)
        for values in incoming:
            item = existing.get(values["external_id"])
            created = item is None
            previous_address = item.address if item is not None else None
            if item is None:
                item = SourceDevice(source_id=source.id, **values)
                database.add(item)
                await database.flush()
            else:
                for key, value in values.items():
                    if key == "address" and value is None:
                        continue
                    setattr(item, key, value)
                new_address = values.get("address")
                if (
                    item.imported_device_id
                    and new_address
                    and new_address != previous_address
                    and not await database.scalar(
                        select(DeviceAddress.id).where(
                            DeviceAddress.address == new_address,
                            DeviceAddress.device_id != item.imported_device_id,
                        )
                    )
                ):
                    imported_address = await database.scalar(
                        select(DeviceAddress).where(
                            DeviceAddress.device_id == item.imported_device_id,
                            DeviceAddress.address == previous_address,
                        )
                    )
                    if imported_address is not None:
                        imported_address.address = new_address
                        imported_address.last_seen_at = now
            item.last_seen_at = now
            if created:
                database.add(
                    NetworkIdentityEvent(
                        source_id=source.id,
                        source_device_id=item.id,
                        kind="identity_seen",
                        name=item.name,
                        new_value=item.address or item.mac_address or "identity only",
                        occurred_at=now,
                    )
                )
            elif values.get("address") and values["address"] != previous_address:
                database.add(
                    NetworkIdentityEvent(
                        source_id=source.id,
                        source_device_id=item.id,
                        kind="address_changed",
                        name=item.name,
                        old_value=previous_address,
                        new_value=values["address"],
                        occurred_at=now,
                    )
                )
            if item.imported_device_id is None:
                matched_device = None
                if item.mac_address:
                    matched_device = await database.scalar(
                        select(Device).where(Device.mac_address == item.mac_address.lower())
                    )
                if matched_device is None and item.address:
                    matched_address = await database.scalar(
                        select(DeviceAddress).where(DeviceAddress.address == item.address)
                    )
                    if matched_address:
                        matched_device = await database.get(Device, matched_address.device_id)
                if matched_device is not None:
                    item.imported_device_id = matched_device.id
                    if not matched_device.mac_address and item.mac_address:
                        matched_device.mac_address = item.mac_address.lower()
        source.last_sync_at = now
        source.last_sync_status = "ok"
        source.last_sync_error = None
        await database.commit()
    except (httpx.HTTPError, OSError, RuntimeError, ValueError, WebSocketException) as error:
        source.last_sync_at = datetime.now(UTC)
        source.last_sync_status = "failed"
        source.last_sync_error = str(error)[:500]
        await database.commit()


async def source_sync_loop() -> None:
    interval = get_settings().source_sync_interval_seconds
    while True:
        try:
            async with get_session_factory()() as database:
                source_ids = list(
                    await database.scalars(
                        select(InventorySource.id).where(InventorySource.enabled.is_(True))
                    )
                )
            for source_id in source_ids:
                async with get_session_factory()() as database:
                    source = await database.get(InventorySource, source_id)
                    if source is not None and source.enabled:
                        await synchronize_source(database, source)
        except Exception:
            logger.exception("inventory source synchronization cycle failed")
        await asyncio.sleep(interval)


@router.get("", response_model=list[SourceView])
async def list_sources(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[SourceView]:
    sources = list(await database.scalars(select(InventorySource).order_by(InventorySource.name)))
    return [await source_view(database, item) for item in sources]


@router.get("/network-inventory", response_model=list[NetworkAssetView])
async def network_inventory(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[NetworkAssetView]:
    devices = list(
        await database.scalars(
            select(Device).options(selectinload(Device.addresses)).order_by(Device.display_name)
        )
    )
    observations = list(await database.scalars(select(SourceDevice)))
    source_names = {
        source.id: source.name for source in await database.scalars(select(InventorySource))
    }
    linked_by_device: dict[uuid.UUID, list[SourceDevice]] = {}
    unlinked_groups: dict[str, list[SourceDevice]] = {}
    for item in observations:
        if item.imported_device_id:
            linked_by_device.setdefault(item.imported_device_id, []).append(item)
        else:
            identity = item.mac_address or item.address or f"{item.source_id}:{item.external_id}"
            unlinked_groups.setdefault(identity.lower(), []).append(item)
    result = []
    for device in devices:
        linked = linked_by_device.get(device.id, [])
        result.append(
            NetworkAssetView(
                id=str(device.id),
                name=device.display_name,
                address=device.addresses[0].address if device.addresses else None,
                mac_address=device.mac_address,
                status=device.status,
                sources=sorted({source_names.get(item.source_id, "Unknown") for item in linked}),
                observations=len(linked),
                linked=True,
                last_seen_at=device.last_seen_at,
                observation_ids=[item.id for item in linked],
            )
        )
    for identity, grouped in unlinked_groups.items():
        recent = max(grouped, key=lambda item: item.last_seen_at)
        result.append(
            NetworkAssetView(
                id=f"observation:{identity}",
                name=recent.name,
                address=next((item.address for item in grouped if item.address), None),
                mac_address=next((item.mac_address for item in grouped if item.mac_address), None),
                status="needs_review",
                sources=sorted({source_names.get(item.source_id, "Unknown") for item in grouped}),
                observations=len(grouped),
                linked=False,
                last_seen_at=max(item.last_seen_at for item in grouped),
                observation_ids=[item.id for item in grouped],
            )
        )
    return sorted(result, key=lambda item: (not item.linked, item.name.lower()))


@router.get("/network-activity", response_model=list[NetworkIdentityEventView])
async def network_activity(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[NetworkIdentityEventView]:
    rows = (
        await database.execute(
            select(NetworkIdentityEvent, InventorySource.name)
            .outerjoin(InventorySource, InventorySource.id == NetworkIdentityEvent.source_id)
            .order_by(NetworkIdentityEvent.occurred_at.desc())
            .limit(500)
        )
    ).all()
    return [
        NetworkIdentityEventView(
            id=event.id,
            kind=event.kind,
            name=event.name,
            source_name=source_name or "Disconnected source",
            old_value=event.old_value,
            new_value=event.new_value,
            occurred_at=event.occurred_at,
        )
        for event, source_name in rows
    ]


@router.post("/network-inventory/link", status_code=204)
async def link_network_identity(
    payload: LinkNetworkIdentityInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    observations = list(
        await database.scalars(
            select(SourceDevice).where(SourceDevice.id.in_(set(payload.observation_ids)))
        )
    )
    if len(observations) != len(set(payload.observation_ids)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "network observation not found")
    device = await database.get(Device, payload.device_id) if payload.device_id else None
    if payload.device_id and device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target device not found")
    recent = max(observations, key=lambda item: item.last_seen_at)
    address = next((item.address for item in observations if item.address), None)
    mac = next((item.mac_address.lower() for item in observations if item.mac_address), None)
    if device is None and mac:
        device = await database.scalar(select(Device).where(Device.mac_address == mac))
    if device is None and address:
        matched_address = await database.scalar(
            select(DeviceAddress).where(DeviceAddress.address == address)
        )
        if matched_address:
            device = await database.get(Device, matched_address.device_id)
    if device is None:
        device = Device(
            display_name=recent.name[:100],
            mac_address=mac,
            device_type="network-device",
            trust=DeviceTrust.unknown,
            criticality="normal",
            monitor_port=None,
            status="unmonitored",
            notes="Promoted from connected network inventory.",
            addresses=[DeviceAddress(address=address, kind="host")] if address else [],
        )
        database.add(device)
        await database.flush()
    else:
        if not device.mac_address and mac:
            duplicate_mac = await database.scalar(
                select(Device.id).where(Device.mac_address == mac, Device.id != device.id)
            )
            if duplicate_mac:
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "MAC address belongs to another canonical device"
                )
            device.mac_address = mac
        if address and not await database.scalar(
            select(DeviceAddress.id).where(DeviceAddress.device_id == device.id)
        ):
            duplicate_address = await database.scalar(
                select(DeviceAddress.id).where(DeviceAddress.address == address)
            )
            if not duplicate_address:
                database.add(DeviceAddress(device_id=device.id, address=address, kind="host"))
    for observation in observations:
        observation.imported_device_id = device.id
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="network.identity.link",
            target_type="device",
            target_id=f"{device.id}:{len(observations)}",
        )
    )
    await database.commit()


@router.post("", response_model=SourceView, status_code=201)
async def create_source(
    payload: SourceInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> SourceView:
    source = InventorySource(
        name=payload.name.strip(),
        kind=payload.kind,
        base_url=(
            pihole_api_base(safe_base_url(str(payload.base_url)))
            if payload.kind == "pihole"
            else safe_base_url(str(payload.base_url))
        ),
        credential_encrypted=encrypt_secret(payload.token.strip()),
    )
    database.add(source)
    await database.flush()
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="source.create",
            target_type="source",
            target_id=str(source.id),
        )
    )
    await database.commit()
    return await source_view(database, source)


@router.post("/{source_id}/sync", response_model=SourceView)
async def sync_source(
    source_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> SourceView:
    source = await database.get(InventorySource, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "inventory source not found")
    await synchronize_source(database, source)
    return await source_view(database, source)


@router.get("/{source_id}/devices", response_model=list[SourceDeviceView])
async def list_source_devices(
    source_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[SourceDevice]:
    return list(
        await database.scalars(
            select(SourceDevice)
            .where(SourceDevice.source_id == source_id)
            .order_by(SourceDevice.name)
        )
    )


@router.post("/{source_id}/import", status_code=204)
async def import_source_devices(
    source_id: uuid.UUID,
    payload: ImportInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    source = await database.get(InventorySource, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "inventory source not found")
    candidates = list(
        await database.scalars(
            select(SourceDevice).where(
                SourceDevice.source_id == source_id, SourceDevice.id.in_(set(payload.ids))
            )
        )
    )
    imported = 0
    for item in candidates:
        if item.imported_device_id:
            continue
        if item.address and not _private_address(item.address):
            continue
        existing_device = None
        if item.mac_address:
            existing_device = await database.scalar(
                select(Device).where(Device.mac_address == item.mac_address.lower())
            )
        if existing_device is None and item.address:
            existing_address = await database.scalar(
                select(DeviceAddress).where(DeviceAddress.address == item.address)
            )
            if existing_address:
                existing_device = await database.get(Device, existing_address.device_id)
        if existing_device:
            item.imported_device_id = existing_device.id
            if not existing_device.mac_address and item.mac_address:
                existing_device.mac_address = item.mac_address.lower()
            continue
        notes = " · ".join(
            value for value in (item.manufacturer, item.model, item.area_name) if value
        )
        device = Device(
            display_name=item.name[:100],
            mac_address=item.mac_address.lower() if item.mac_address else None,
            device_type="pihole-client" if source.kind == "pihole" else "home-assistant",
            trust=DeviceTrust.unknown,
            criticality="normal",
            monitor_port=None,
            notes=f"Imported from {source.name}{': ' + notes if notes else ''}",
            addresses=[DeviceAddress(address=item.address, kind="host")] if item.address else [],
        )
        database.add(device)
        await database.flush()
        item.imported_device_id = device.id
        imported += 1
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="source.devices.import",
            target_type="source",
            target_id=f"{source_id}:{imported}",
        )
    )
    await database.commit()


@router.delete("/{source_id}", status_code=204)
async def delete_source(
    source_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    source = await database.get(InventorySource, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "inventory source not found")
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="source.delete",
            target_type="source",
            target_id=str(source.id),
        )
    )
    await database.delete(source)
    await database.commit()
