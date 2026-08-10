import asyncio
import ipaddress
import logging
import socket
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from sentinel.config import get_settings
from sentinel.database import get_session_factory
from sentinel.incidents import record_monitor_transition
from sentinel.models import AgentMetric, Device, MonitorResult, ServiceMonitor

logger = logging.getLogger(__name__)


def is_internal_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_private or address.is_loopback or address.is_link_local


async def resolve_target(target: str, scope: str = "internal") -> str:
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    candidates = {ipaddress.ip_address(address[4][0]) for address in addresses}
    if scope == "internal" and candidates and all(is_internal_address(item) for item in candidates):
        return str(next(iter(candidates)))
    if scope == "external" and candidates and all(item.is_global for item in candidates):
        return str(next(iter(candidates)))
    expected = "private/local" if scope == "internal" else "public"
    raise ValueError(f"target did not resolve exclusively to {expected} network addresses")


async def resolve_safe_target(target: str) -> str:
    return await resolve_target(target, "internal")


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


async def check_service(monitor: ServiceMonitor) -> MonitorResult:
    checked_at = datetime.now(UTC)
    monitor.last_checked_at = checked_at
    started = time.perf_counter()
    status_code = None
    response_ms = None
    failure_reason = None
    success = False
    try:
        parsed = urlsplit(monitor.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must use HTTP or HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("URL credentials are not allowed")
        await resolve_target(parsed.hostname, monitor.target_scope or "internal")
        async with httpx.AsyncClient(
            timeout=monitor.timeout_seconds,
            verify=monitor.verify_tls,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(monitor.url)
        response_ms = max(1, round((time.perf_counter() - started) * 1000))
        status_code = response.status_code
        if status_code != monitor.expected_status:
            failure_reason = f"expected HTTP {monitor.expected_status}, received {status_code}"
        elif monitor.expected_text and monitor.expected_text not in response.text:
            failure_reason = "expected response text was not found"
        else:
            success = True
    except ValueError as exc:
        failure_reason = str(exc)
    except httpx.TimeoutException:
        failure_reason = "request timed out"
    except httpx.HTTPError:
        failure_reason = "request failed"

    monitor.last_response_ms = response_ms
    monitor.last_status_code = status_code
    monitor.last_failure_reason = failure_reason
    if success:
        monitor.status = "up"
        monitor.last_success_at = checked_at
        monitor.outage_started_at = None
    else:
        monitor.status = "down"
        monitor.outage_started_at = monitor.outage_started_at or checked_at
    return MonitorResult(
        monitor_id=monitor.id,
        checked_at=checked_at,
        success=success,
        response_ms=response_ms,
        status_code=status_code,
        failure_reason=failure_reason,
    )


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


async def monitor_all_services() -> None:
    async with get_session_factory()() as database:
        monitors = list(
            await database.scalars(select(ServiceMonitor).where(ServiceMonitor.enabled.is_(True)))
        )
        for monitor in monitors:
            previous_status = monitor.status
            result = await check_service(monitor)
            database.add(result)
            await record_monitor_transition(database, monitor, previous_status, result.checked_at)
        await database.commit()


async def remove_expired_agent_metrics() -> int:
    cutoff = datetime.now(UTC) - timedelta(days=get_settings().detailed_retention_days)
    async with get_session_factory()() as database:
        result = await database.execute(
            delete(AgentMetric).where(AgentMetric.collected_at < cutoff)
        )
        await database.commit()
        return result.rowcount or 0


async def monitoring_loop(interval_seconds: int = 30) -> None:
    next_retention = 0.0
    while True:
        try:
            await asyncio.gather(monitor_all_devices(), monitor_all_services())
            if time.monotonic() >= next_retention:
                await remove_expired_agent_metrics()
                next_retention = time.monotonic() + 3600
        except Exception:
            logger.exception("monitoring cycle failed")
        await asyncio.sleep(interval_seconds)
