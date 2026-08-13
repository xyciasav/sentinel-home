import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sentinel.sources import (
    aggregate_pihole_queries,
    analyze_pihole_traffic,
    correlate_traffic_clients,
    parse_pihole_devices,
    parse_pihole_traffic,
    pihole_api_base,
    safe_base_url,
    traffic_diagnostics,
    traffic_signals,
    websocket_url,
)


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


def test_pihole_login_url_is_normalized_to_api_origin() -> None:
    assert pihole_api_base("http://pi.hole/admin/login.php") == "http://pi.hole"


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


def test_parse_pihole_traffic_normalizes_rankings() -> None:
    traffic = parse_pihole_traffic(
        {
            "domains": {
                "top_domains": [{"domain": "example.com", "count": 12}],
            }
        },
        {"clients": {"top_sources": {"10.0.0.5": 19}}},
        {"domains": [{"domain": "ads.example", "count": 7}]},
    )
    assert traffic["top_domains"] == [{"domain": "example.com", "count": 12}]
    assert traffic["top_blocked_domains"] == [{"domain": "ads.example", "count": 7}]
    assert traffic["top_clients"] == [{"client": "10.0.0.5", "count": 19}]


def test_pihole_analysis_detects_query_spike_after_baseline() -> None:
    previous = {
        "traffic_baseline": {
            "samples": 4,
            "queries_per_interval": 100,
            "blocked_percent": 10,
            "last_total": 500,
        },
        "traffic": {"top_domains": []},
    }
    current = {
        "queries": {"total": 900, "blocked": 90},
        "traffic": {"top_domains": []},
    }
    analyzed = analyze_pihole_traffic(current, previous)
    assert analyzed["traffic"]["anomalies"][0]["kind"] == "query_spike"
    assert analyzed["traffic_baseline"]["samples"] == 5


def test_pihole_diagnostics_explains_privacy_filtered_rankings() -> None:
    diagnostics = traffic_diagnostics(
        500,
        {
            "top_domains": [],
            "top_blocked_domains": [],
            "top_clients": [],
            "api_mode": "v6",
            "endpoint_status": {"domains": 200, "clients": 200},
        },
    )
    assert "no readable recent query-log entries" in diagnostics[0]


def test_pihole_diagnostics_identifies_legacy_api_fallback() -> None:
    diagnostics = traffic_diagnostics(
        500,
        {
            "top_domains": [],
            "top_blocked_domains": [],
            "top_clients": [],
            "api_mode": "legacy",
        },
    )
    assert "application password" in diagnostics[0]


def test_pihole_query_log_fallback_builds_rankings() -> None:
    traffic = aggregate_pihole_queries(
        [
            {
                "domain": "example.com",
                "status": "FORWARDED",
                "client": {"ip": "10.0.0.5", "name": "laptop"},
            },
            {
                "domain": "ads.example",
                "status": "GRAVITY",
                "client": {"ip": "10.0.0.5", "name": "laptop"},
            },
            {"domain": "example.com", "status": "CACHE", "client": {"ip": "10.0.0.6"}},
        ]
    )
    assert traffic["top_domains"][0] == {"domain": "example.com", "count": 2}
    assert traffic["top_blocked_domains"][0]["domain"] == "ads.example"
    assert traffic["top_clients"][0] == {"client": "laptop", "count": 2}
    assert traffic["sample"]["queries"] == 3
    assert traffic["sample"]["unique_domains"] == 2


def test_pihole_query_log_accepts_legacy_string_client() -> None:
    traffic = aggregate_pihole_queries(
        [{"domain": "example.com", "status": "FORWARDED", "client": "10.0.0.8"}]
    )
    assert traffic["top_clients"] == [{"client": "10.0.0.8", "count": 1}]


def test_pihole_diagnostics_prioritizes_sync_failure() -> None:
    assert traffic_diagnostics(100, {}, "authentication failed") == [
        "Pi-hole synchronization failed: authentication failed"
    ]


def test_pihole_signals_identify_chatty_client_and_nxdomain_rate() -> None:
    signals = traffic_signals(200, 10, 40, 0, "camera.lan", 150)
    assert {item["kind"] for item in signals} == {"nxdomain_rate", "chatty_client"}


def test_pihole_clients_correlate_to_canonical_device() -> None:
    device_id = uuid.uuid4()
    traffic = {
        "top_clients": [{"client": "camera.lan", "count": 50}],
        "client_profiles": [{"client": "camera.lan", "address": "10.0.0.44", "queries": 50}],
    }
    correlate_traffic_clients(
        traffic,
        [SimpleNamespace(id=device_id, display_name="Driveway Camera", hostname="camera.lan")],
        [SimpleNamespace(address="10.0.0.44", device_id=device_id)],
    )
    assert traffic["top_clients"][0]["device_name"] == "Driveway Camera"
    assert traffic["top_clients"][0]["device_id"] == str(device_id)
