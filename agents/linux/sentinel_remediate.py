#!/usr/bin/env python3
"""Root-owned Sentinel package remediation helper with a fixed operation surface."""

import json
import os
import re
import subprocess
import sys

PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.:_-]{0,254}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,254}$")
HELPER_VERSION = "0.3.3"


def installed_version(package: str) -> str:
    output = subprocess.run(  # noqa: S603
        ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}", package],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.strip()
    status, _, version = output.partition("\t")
    if not status.startswith("ii") or not version:
        raise ValueError(f"package is not fully installed: {package} ({status.strip()})")
    return version


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
    environment = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    print("[1/5] Refreshing package repositories", flush=True)
    subprocess.run(  # noqa: S603
        ["/usr/bin/apt-get", "update"],
        env=environment,
        timeout=600,
        check=True,
    )
    policy = subprocess.run(  # noqa: S603
        ["/usr/bin/apt-cache", "policy", package],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    candidate = next(
        (
            line.split(":", 1)[1].strip()
            for line in policy.splitlines()
            if line.strip().startswith("Candidate:")
        ),
        "",
    )
    if not candidate or candidate == "(none)" or candidate == current:
        raise RuntimeError(
            f"no repository upgrade candidate for {package}; "
            f"installed and candidate are {current}. "
            "This package may be left over from an older OS release and requires manual review."
        )
    print("[2/5] Configuring any unpacked packages", flush=True)
    subprocess.run(  # noqa: S603
        ["/usr/bin/dpkg", "--configure", "--pending"],
        env=environment,
        timeout=900,
        check=False,
    )
    print("[3/5] Repairing interrupted package dependencies", flush=True)
    subprocess.run(  # noqa: S603
        ["/usr/bin/apt-get", "--fix-broken", "install", "--assume-yes"],
        env=environment,
        timeout=900,
        check=True,
    )
    print(f"[4/5] Upgrading {package} and required dependencies", flush=True)
    subprocess.run(  # noqa: S603
        ["/usr/bin/apt-get", "install", "--only-upgrade", "--assume-yes", package],
        env=environment,
        timeout=900,
        check=True,
    )
    print("[5/5] Verifying installed package version", flush=True)
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
    if sys.argv[1:] == ["--version"]:
        print(HELPER_VERSION)
        raise SystemExit(0)
    try:
        raise SystemExit(run())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"remediation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
