import asyncio
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    AuditEvent,
    Device,
    DeviceAddress,
    DeviceTrust,
    DiscoveredHost,
    DiscoveryRun,
    Session,
    User,
)

router = APIRouter(prefix="/api/v1/discovery", tags=["network discovery"])
SAFE_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8123)


class DiscoveryInput(BaseModel):
    subnet: str = Field(max_length=50)


class HostView(BaseModel):
    id: uuid.UUID
    address: str
    open_ports: list[int]
    state: str
    device_id: uuid.UUID | None
    discovered_at: datetime


class RunView(BaseModel):
    id: uuid.UUID
    subnet: str
    status: str
    hosts_checked: int
    hosts_found: int
    started_at: datetime
    completed_at: datetime | None
    hosts: list[HostView]


def host_view(host: DiscoveredHost) -> HostView:
    return HostView(
        id=host.id,
        address=host.address,
        open_ports=[int(port) for port in host.open_ports.split(",") if port],
        state=host.state,
        device_id=host.device_id,
        discovered_at=host.discovered_at,
    )


async def probe_host(address: str) -> list[int]:
    open_ports = []
    for port in SAFE_PORTS:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), 0.35)
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except (TimeoutError, OSError):
            pass
    return open_ports


def validated_subnet(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid IPv4 subnet") from error
    if not isinstance(network, ipaddress.IPv4Network) or not network.is_private:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "subnet must be private IPv4")
    if network.num_addresses > 256:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "maximum discovery size is /24")
    return network


@router.post("/runs", response_model=RunView, status_code=201)
async def run_discovery(
    payload: DiscoveryInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RunView:
    network = validated_subnet(payload.subnet)
    addresses = [str(address) for address in network.hosts()]
    run = DiscoveryRun(subnet=str(network), hosts_checked=len(addresses))
    database.add(run)
    await database.flush()
    semaphore = asyncio.Semaphore(32)

    async def limited_probe(address: str) -> tuple[str, list[int]]:
        async with semaphore:
            return address, await probe_host(address)

    results = await asyncio.gather(*(limited_probe(address) for address in addresses))
    known = {
        item.address: item.device_id
        for item in await database.scalars(
            select(DeviceAddress).where(DeviceAddress.address.in_(addresses))
        )
    }
    hosts = []
    for address, ports in results:
        if not ports:
            continue
        host = DiscoveredHost(
            run_id=run.id,
            address=address,
            open_ports=",".join(map(str, ports)),
            state="known" if address in known else "new",
            device_id=known.get(address),
        )
        database.add(host)
        hosts.append(host)
    run.hosts_found = len(hosts)
    run.status = "complete"
    run.completed_at = datetime.now(UTC)
    database.add(
        AuditEvent(
            actor_user_id=authenticated[0].id,
            action="discovery.run",
            target_type="subnet",
            target_id=str(network),
        )
    )
    await database.commit()
    return RunView(
        **{field: getattr(run, field) for field in RunView.model_fields if field != "hosts"},
        hosts=[host_view(host) for host in hosts],
    )


@router.get("/latest", response_model=RunView | None)
async def latest_discovery(
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> RunView | None:
    run = await database.scalar(
        select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(1)
    )
    if run is None:
        return None
    hosts = list(
        await database.scalars(select(DiscoveredHost).where(DiscoveredHost.run_id == run.id))
    )
    return RunView(
        **{field: getattr(run, field) for field in RunView.model_fields if field != "hosts"},
        hosts=[host_view(host) for host in hosts],
    )


@router.post("/hosts/{host_id}/add", response_model=HostView)
async def add_discovered_host(
    host_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> HostView:
    host = await database.get(DiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "discovered host not found")
    if host.device_id is None:
        device = Device(
            display_name=f"Device {host.address}",
            trust=DeviceTrust.unknown,
            criticality="normal",
            monitor_port=int(host.open_ports.split(",")[0]),
            addresses=[DeviceAddress(address=host.address, kind="host")],
        )
        database.add(device)
        await database.flush()
        host.device_id = device.id
        host.state = "added"
        database.add(
            AuditEvent(
                actor_user_id=authenticated[0].id,
                action="discovery.add_device",
                target_type="device",
                target_id=str(device.id),
            )
        )
        await database.commit()
    return host_view(host)
