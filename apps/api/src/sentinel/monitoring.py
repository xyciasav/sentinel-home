import asyncio
import ipaddress
import logging
import socket
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from sentinel.database import get_session_factory
from sentinel.models import Device

logger = logging.getLogger(__name__)


async def resolve_safe_target(target: str) -> str:
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    for address in addresses:
        candidate = ipaddress.ip_address(address[4][0])
        if candidate.is_private or candidate.is_loopback or candidate.is_link_local:
            return str(candidate)
    raise ValueError("target did not resolve to a private network address")


async def check_device(device: Device) -> None:
    device.last_checked_at = datetime.now(UTC)
    if not device.addresses or not device.monitor_port:
        device.status = "unmonitored"
        device.last_failure_reason = None
        return
    started = time.perf_counter()
    try:
        target = await resolve_safe_target(device.addresses[0].address)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target, device.monitor_port), timeout=3
        )
        writer.close()
        await writer.wait_closed()
        device.status = "online"
        device.last_latency_ms = max(1, round((time.perf_counter() - started) * 1000))
        device.last_failure_reason = None
    except TimeoutError:
        device.status = "offline"
        device.last_latency_ms = None
        device.last_failure_reason = "connection timed out"
    except (OSError, ValueError):
        device.status = "offline"
        device.last_latency_ms = None
        device.last_failure_reason = "connection failed"


async def monitor_all_devices() -> None:
    async with get_session_factory()() as database:
        devices = list(
            await database.scalars(select(Device).options(selectinload(Device.addresses)))
        )
        semaphore = asyncio.Semaphore(10)

        async def limited_check(device: Device) -> None:
            async with semaphore:
                await check_device(device)

        await asyncio.gather(*(limited_check(device) for device in devices))
        await database.commit()


async def monitoring_loop(interval_seconds: int = 30) -> None:
    while True:
        try:
            await monitor_all_devices()
        except Exception:
            logger.exception("device monitoring cycle failed")
        await asyncio.sleep(interval_seconds)
