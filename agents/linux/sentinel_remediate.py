#!/usr/bin/env python3
"""Root-owned Sentinel package remediation helper with a fixed operation surface."""

import json
import re
import subprocess
import sys

PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.:_-]{0,254}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,254}$")


def installed_version(package: str) -> str:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.strip()


def run() -> int:
    raw = sys.stdin.read(4097)
    if len(raw) > 4096:
        raise ValueError("payload too large")
    payload = json.loads(raw)
    if set(payload) != {"operation", "package_name", "installed_version", "target_version"}:
        raise ValueError("unexpected payload fields")
    if payload["operation"] != "package_upgrade":
        raise ValueError("unsupported operation")
    package = payload["package_name"]
    expected, target = payload["installed_version"], payload["target_version"]
    if not isinstance(package, str) or not PACKAGE.fullmatch(package):
        raise ValueError("invalid package name")
    if not all(isinstance(item, str) and VERSION.fullmatch(item) for item in (expected, target)):
        raise ValueError("invalid package version")
    current = installed_version(package)
    if current != expected:
        raise ValueError(f"installed version changed: expected {expected}, found {current}")
    subprocess.run(  # noqa: S603
        ["/usr/bin/apt-get", "update"],
        timeout=600,
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["/usr/bin/apt-get", "install", "--only-upgrade", "--assume-yes", package],
        timeout=900,
        check=True,
    )
    updated = installed_version(package)
    if updated == current:
        raise RuntimeError(
            f"repository did not provide an upgrade for {package}; still at {updated} "
            f"(advisory fix threshold {target})"
        )
    print(
        f"verified repository upgrade {package} {current} -> {updated}; "
        f"advisory fix threshold {target} will be confirmed by the next package scan"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"remediation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
