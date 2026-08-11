import ast
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sentinel.agents import HeartbeatInput, sign_command
from sentinel.security import hash_secret


def test_linux_agent_postpones_newer_type_annotation_evaluation() -> None:
    source = Path("agents/linux/sentinel_agent.py").read_text(encoding="utf-8")

    assert "from __future__ import annotations" in source
    assert 'VERSION = "0.5.0"' in source
    assert "verify_command" in source
    ast.parse(source, feature_version=(3, 8))


def test_remediation_helper_has_no_shell_execution_surface() -> None:
    source = Path("agents/linux/sentinel_remediate.py").read_text(encoding="utf-8")

    assert "shell=True" not in source
    assert 'payload["operation"] != "package_upgrade"' in source
    assert '["/usr/bin/apt-get", "update"]' in source


def test_container_helper_has_fixed_read_only_docker_commands() -> None:
    source = Path("agents/linux/sentinel_containers.py").read_text(encoding="utf-8")

    assert "shell=True" not in source
    assert '["/usr/bin/docker", "ps", "-aq", "--no-trunc"]' in source
    assert '["/usr/bin/docker", "inspect", *ids[:2_000]]' in source


def test_remediation_commands_are_bound_to_agent_credential() -> None:
    plan = SimpleNamespace(
        id=uuid4(),
        operation="package_upgrade",
        package_name="openssl",
        installed_version="1.0",
        target_version="1.1",
    )
    first = SimpleNamespace(credential_fingerprint=hash_secret("first-token"))
    second = SimpleNamespace(credential_fingerprint=hash_secret("second-token"))

    assert sign_command(plan, first) != sign_command(plan, second)


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
        hostname="server-one",
        os_name="debian",
        os_version="12",
        kernel_version="6.1.0",
        packages=[{"name": "openssl", "version": "3.0", "manager": "dpkg"}],
    )

    assert heartbeat.packages and heartbeat.packages[0].name == "openssl"
    assert heartbeat.os_name == "debian"


def test_agent_heartbeat_accepts_container_inventory() -> None:
    heartbeat = HeartbeatInput(
        version="0.5.0",
        cpu_percent=10,
        memory_percent=20,
        memory_used_bytes=1,
        memory_total_bytes=2,
        disk_percent=30,
        disk_free_bytes=1,
        disk_total_bytes=2,
        uptime_seconds=60,
        containers=[
            {
                "container_id": "a" * 64,
                "name": "sonarr",
                "image": "linuxserver/sonarr:latest",
                "state": "running",
                "health": "healthy",
            }
        ],
    )

    assert heartbeat.containers and heartbeat.containers[0].name == "sonarr"
