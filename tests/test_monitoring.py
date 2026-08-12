import uuid

from sentinel.models import Device, ServiceMonitor
from sentinel.monitoring import check_device, check_service, resolve_target


async def test_device_without_port_is_unmonitored() -> None:
    device = Device(display_name="Pi", monitor_port=None, addresses=[])
    await check_device(device)
    assert device.status == "unmonitored"
    assert device.last_checked_at is not None


async def test_service_rejects_public_targets() -> None:
    monitor = ServiceMonitor(
        id=uuid.uuid4(),
        name="Public target",
        url="https://8.8.8.8/",
        expected_status=200,
        timeout_seconds=1,
        verify_tls=True,
    )
    result = await check_service(monitor)
    assert result.success is False
    assert monitor.status == "retrying"
    assert monitor.outage_started_at is None
    assert monitor.consecutive_failures == 1
    assert monitor.last_failure_reason == (
        "target did not resolve exclusively to private/local network addresses"
    )


async def test_service_only_goes_down_after_failure_threshold() -> None:
    monitor = ServiceMonitor(
        id=uuid.uuid4(),
        name="Private target",
        url="https://8.8.8.8/",
        expected_status=200,
        timeout_seconds=1,
        failure_threshold=2,
        retry_interval_seconds=30,
        verify_tls=True,
    )
    await check_service(monitor)
    assert monitor.status == "retrying"
    await check_service(monitor)
    assert monitor.status == "down"
    assert monitor.outage_started_at is not None


async def test_external_scope_accepts_only_public_targets() -> None:
    assert await resolve_target("8.8.8.8", "external") == "8.8.8.8"

    try:
        await resolve_target("127.0.0.1", "external")
    except ValueError as error:
        assert "public network addresses" in str(error)
    else:
        raise AssertionError("external monitoring accepted a loopback target")
