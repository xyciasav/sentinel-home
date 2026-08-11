import ipaddress
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    AuditEvent,
    Device,
    DeviceAddress,
    DeviceTrust,
    InventorySource,
    Session,
    SourceDevice,
    User,
)
from sentinel.security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/v1/sources", tags=["inventory sources"])


class SourceInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    base_url: AnyHttpUrl
    token: str = Field(min_length=20, max_length=1000)


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


def safe_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid Home Assistant URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        allowed = address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        allowed = parsed.hostname.endswith(".local") or "." not in parsed.hostname
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
        importable_count=sum(
            bool(item.address and not item.imported_device_id) for item in devices
        ),
        imported_count=sum(bool(item.imported_device_id) for item in devices),
    )


@router.get("", response_model=list[SourceView])
async def list_sources(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[SourceView]:
    sources = list(await database.scalars(select(InventorySource).order_by(InventorySource.name)))
    return [await source_view(database, item) for item in sources]


@router.post("", response_model=SourceView, status_code=201)
async def create_source(
    payload: SourceInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> SourceView:
    source = InventorySource(
        name=payload.name.strip(),
        base_url=safe_base_url(str(payload.base_url)),
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
    try:
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
            if item is None:
                item = SourceDevice(source_id=source.id, **values)
                database.add(item)
            else:
                for key, value in values.items():
                    setattr(item, key, value)
            item.last_seen_at = now
        source.last_sync_at = now
        source.last_sync_status = "ok"
        source.last_sync_error = None
        await database.commit()
    except (httpx.HTTPError, OSError, RuntimeError, ValueError, WebSocketException) as error:
        source.last_sync_at = datetime.now(UTC)
        source.last_sync_status = "failed"
        source.last_sync_error = str(error)[:500]
        await database.commit()
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
    candidates = list(
        await database.scalars(
            select(SourceDevice).where(
                SourceDevice.source_id == source_id, SourceDevice.id.in_(set(payload.ids))
            )
        )
    )
    imported = 0
    for item in candidates:
        if item.imported_device_id or not item.address or not _private_address(item.address):
            continue
        existing = await database.scalar(
            select(DeviceAddress).where(DeviceAddress.address == item.address)
        )
        if existing:
            item.imported_device_id = existing.device_id
            continue
        notes = " · ".join(
            value for value in (item.manufacturer, item.model, item.area_name) if value
        )
        device = Device(
            display_name=item.name[:100],
            device_type="home-assistant",
            trust=DeviceTrust.unknown,
            criticality="normal",
            monitor_port=None,
            notes=f"Imported from Home Assistant{': ' + notes if notes else ''}",
            addresses=[DeviceAddress(address=item.address, kind="host")],
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
