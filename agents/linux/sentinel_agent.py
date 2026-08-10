#!/usr/bin/env python3
"""Sentinel Home Linux telemetry agent. Uses only the Python standard library."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "0.2.0"


def request(url: str, payload: dict, token: str | None = None) -> dict:
    if not url.startswith(("https://", "http://")):
        raise ValueError("unsupported server URL scheme")
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "User-Agent": f"sentinel-linux-agent/{VERSION}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    outbound = urllib.request.Request(url, data=data, headers=headers)  # noqa: S310
    with urllib.request.urlopen(outbound, timeout=30) as response:  # noqa: S310
        body = response.read()
        return json.loads(body) if body else {}


def cpu_sample() -> tuple[int, int]:
    values = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def cpu_percent() -> int:
    total_a, idle_a = cpu_sample()
    time.sleep(0.2)
    total_b, idle_b = cpu_sample()
    elapsed = max(total_b - total_a, 1)
    return max(0, min(100, round(100 * (elapsed - (idle_b - idle_a)) / elapsed)))


def memory() -> tuple[int, int, int]:
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        values[key] = int(value.strip().split()[0]) * 1024
    total, available = values["MemTotal"], values.get("MemAvailable", values.get("MemFree", 0))
    used = total - available
    return round(used * 100 / total), used, total


def packages() -> list[dict[str, str | None]]:
    if shutil.which("dpkg-query"):
        command = ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n"]
        manager = "dpkg"
    elif shutil.which("rpm"):
        command = ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]
        manager = "rpm"
    else:
        return []
    # Command is selected from the fixed package-manager argv above; no input reaches the shell.
    output = subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, timeout=120, check=True
    ).stdout
    result = []
    for line in output.splitlines()[:20_000]:
        parts = line.split("\t")
        if len(parts) >= 2:
            result.append(
                {
                    "name": parts[0][:255],
                    "version": parts[1][:255],
                    "architecture": parts[2][:50] if len(parts) > 2 else None,
                    "manager": manager,
                }
            )
    return result


def telemetry(include_packages: bool) -> dict:
    memory_percent, memory_used, memory_total = memory()
    disk = shutil.disk_usage("/")
    payload = {
        "version": VERSION,
        "cpu_percent": cpu_percent(),
        "memory_percent": memory_percent,
        "memory_used_bytes": memory_used,
        "memory_total_bytes": memory_total,
        "disk_percent": round(disk.used * 100 / disk.total),
        "disk_free_bytes": disk.free,
        "disk_total_bytes": disk.total,
        "uptime_seconds": round(float(Path("/proc/uptime").read_text().split()[0])),
        "hostname": platform.node(),
        "kernel_version": platform.release(),
    }
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError:
        pass
    payload["os_name"] = os_release.get("ID") or platform.system()
    payload["os_version"] = os_release.get("VERSION_ID") or platform.version()
    if include_packages:
        payload["packages"] = packages()
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--state",
        default=os.getenv(
            "SENTINEL_AGENT_STATE", str(Path.home() / ".local/state/sentinel-agent/token")
        ),
    )
    parser.add_argument("--enroll-only", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    base_url = os.environ["SENTINEL_URL"].rstrip("/")
    if (
        not base_url.startswith("https://")
        and os.getenv("SENTINEL_ALLOW_HTTP", "").lower() != "true"
    ):
        raise SystemExit("HTTPS is required; set SENTINEL_ALLOW_HTTP=true only on a trusted LAN")
    state = Path(args.state)
    if state.exists():
        token = state.read_text().strip()
    else:
        enrollment = os.environ.get("SENTINEL_ENROLLMENT_TOKEN")
        if not enrollment:
            raise SystemExit("SENTINEL_ENROLLMENT_TOKEN is required for first enrollment")
        claimed = request(
            f"{base_url}/api/v1/agents/claim",
            {
                "enrollment_token": enrollment,
                "version": VERSION,
                "platform": f"linux/{platform.machine()}",
            },
        )
        token = claimed["agent_token"]
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(token)
        state.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if args.enroll_only:
        return
    next_packages = 0.0
    while True:
        try:
            now = time.time()
            include_packages = now >= next_packages
            request(f"{base_url}/api/v1/agents/heartbeat", telemetry(include_packages), token)
            if include_packages:
                next_packages = now + 21_600
        except (OSError, ValueError, subprocess.SubprocessError, urllib.error.URLError) as error:
            print(f"heartbeat failed: {error}", flush=True)
        if args.once:
            return
        time.sleep(15)


if __name__ == "__main__":
    main()
