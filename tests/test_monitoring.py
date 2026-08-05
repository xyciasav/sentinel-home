from sentinel.models import Device
from sentinel.monitoring import check_device


async def test_device_without_port_is_unmonitored() -> None:
    device = Device(display_name="Pi", monitor_port=None, addresses=[])
    await check_device(device)
    assert device.status == "unmonitored"
    assert device.last_checked_at is not None
