import pytest
from fastapi import HTTPException
from sentinel.sources import safe_base_url, websocket_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://10.0.0.20:8123/", "http://10.0.0.20:8123"),
        ("https://homeassistant.local", "https://homeassistant.local"),
        ("http://homeassistant:8123", "http://homeassistant:8123"),
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
