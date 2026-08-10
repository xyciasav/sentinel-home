from pathlib import Path

import pytest
from pydantic import ValidationError
from sentinel.agents import HeartbeatInput


def test_linux_agent_postpones_newer_type_annotation_evaluation() -> None:
    source = Path("agents/linux/sentinel_agent.py").read_text(encoding="utf-8")

    assert "from __future__ import annotations" in source
    assert 'VERSION = "0.1.1"' in source


def test_agent_heartbeat_validates_resource_ranges() -> None:
    with pytest.raises(ValidationError):
        HeartbeatInput(
            version="0.1.0",
            cpu_percent=101,
            memory_percent=10,
            memory_used_bytes=1,
            memory_total_bytes=2,
            disk_percent=10,
            disk_free_bytes=1,
            disk_total_bytes=2,
            uptime_seconds=1,
        )


def test_agent_heartbeat_accepts_package_inventory() -> None:
    heartbeat = HeartbeatInput(
        version="0.1.0",
        cpu_percent=10,
        memory_percent=20,
        memory_used_bytes=1,
        memory_total_bytes=2,
        disk_percent=30,
        disk_free_bytes=1,
        disk_total_bytes=2,
        uptime_seconds=60,
        packages=[{"name": "openssl", "version": "3.0", "manager": "dpkg"}],
    )

    assert heartbeat.packages and heartbeat.packages[0].name == "openssl"
