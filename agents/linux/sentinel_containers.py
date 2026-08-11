#!/usr/bin/env python3
"""Read-only root helper for Docker container inventory."""

import json
import re
import subprocess
import sys

CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")


def run() -> int:
    listing = subprocess.run(  # noqa: S603
        ["/usr/bin/docker", "ps", "-aq", "--no-trunc"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    ids = [item for item in listing.stdout.splitlines() if CONTAINER_ID.fullmatch(item)]
    if not ids:
        print("[]")
        return 0
    inspected = subprocess.run(  # noqa: S603
        ["/usr/bin/docker", "inspect", *ids[:2_000]],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    result = []
    for item in json.loads(inspected.stdout):
        state = item.get("State", {})
        config = item.get("Config", {})
        network = item.get("NetworkSettings", {})
        ports = []
        for private, bindings in (network.get("Ports") or {}).items():
            if not bindings:
                ports.append(private)
            else:
                ports.extend(
                    f"{binding.get('HostIp') or '0.0.0.0'}:{binding.get('HostPort')}->{private}"  # noqa: S104 -- display Docker's wildcard binding
                    for binding in bindings
                )
        result.append(
            {
                "container_id": str(item.get("Id", ""))[:64],
                "name": str(item.get("Name", "")).lstrip("/")[:255],
                "image": str(config.get("Image") or item.get("Image", ""))[:500],
                "state": str(state.get("Status", "unknown"))[:30],
                "health": str((state.get("Health") or {}).get("Status"))[:30]
                if state.get("Health")
                else None,
                "status": str(state.get("Error") or state.get("Status", "unknown"))[:500],
                "ports": ", ".join(ports)[:1000],
                "restart_count": max(0, int(item.get("RestartCount") or 0)),
            }
        )
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"container inventory failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
