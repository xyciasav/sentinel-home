import pytest
from fastapi import HTTPException
from sentinel.sources import parse_pihole_devices, safe_base_url, websocket_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://10.0.0.20:8123/", "http://10.0.0.20:8123"),
        ("https://homeassistant.local", "https://homeassistant.local"),
        ("http://homeassistant:8123", "http://homeassistant:8123"),
        ("https://pi.hole", "https://pi.hole"),
    ],
)
def test_safe_base_url_accepts_local_destinations(value: str, expected: str) -> None:
    assert safe_base_url(value) == expected


@pytest.mark.parametrize(
    "value", ["https://example.com", "ftp://10.0.0.20", "http://user@10.0.0.20"]
)
def test_safe_base_url_rejects_unsafe_destinations(value: str) -> None:
    with pytest.raises(HTTPException):
        safe_base_url(value)


def test_websocket_url_uses_home_assistant_endpoint() -> None:
    assert websocket_url("https://homeassistant.local") == "wss://homeassistant.local/api/websocket"


def test_parse_pihole_devices_prefers_recent_private_address() -> None:
    devices = parse_pihole_devices(
        [
            {
                "id": 7,
                "hwaddr": "00:11:22:33:44:55",
                "interface": "eth0",
                "macVendor": "Example Vendor",
                "ips": [
                    {"ip": "192.168.1.20", "name": "media-server", "lastSeen": 20},
                    {"ip": "8.8.8.8", "name": None, "lastSeen": 30},
                ],
            }
        ]
    )

    assert devices[0]["external_id"] == "7"
    assert devices[0]["name"] == "media-server"
    assert devices[0]["address"] == "192.168.1.20"
    assert devices[0]["manufacturer"] == "Example Vendor"
