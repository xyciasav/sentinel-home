import uuid

from sentinel.models import Device, ServiceMonitor
from sentinel.monitoring import check_device, check_service


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
    assert monitor.status == "down"
    assert monitor.outage_started_at is not None
    assert monitor.last_failure_reason == "target did not resolve to a private network address"
