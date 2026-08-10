import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.config import get_settings
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    DeviceAddress,
    DiscoveredHost,
    InstalledPackage,
    Session,
    User,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


class FindingView(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID | None
    address: str
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: str | None
    known_exploited: bool
    required_action: str | None
    action_due: str | None
    cpe: str
    status: str
    user_notes: str | None
    affected_package: str | None
    installed_version: str | None
    fixed_version: str | None
    detection_method: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class FindingUpdate(BaseModel):
    status: str = Field(
        pattern=r"^(open|investigating|accepted_risk|false_positive|resolved|ignored)$"
    )
    user_notes: str | None = Field(default=None, max_length=4000)


def cvss(cve: dict) -> tuple[str, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            return str(data.get("baseSeverity", "unknown")).lower(), str(
                data.get("baseScore", "")
            ) or None
    return "unknown", None


def osv_ecosystem(os_name: str | None, os_version: str | None) -> str | None:
    name = (os_name or "").lower()
    version = (os_version or "").split(" ", 1)[0]
    major = version.split(".", 1)[0]
    if name == "debian" and major.isdigit():
        return f"Debian:{major}"
    if name == "ubuntu" and len(version.split(".")) == 2:
        year, month = version.split(".")
        if year.isdigit() and month.isdigit():
            lts = ":LTS" if int(year) % 2 == 0 and month == "04" else ""
            return f"Ubuntu:{version}{lts}"
    return None


def osv_severity(advisory: dict) -> str:
    candidates = [
        advisory.get("database_specific", {}).get("severity"),
        advisory.get("database_specific", {}).get("priority"),
    ]
    for affected in advisory.get("affected", []):
        candidates.append(affected.get("ecosystem_specific", {}).get("severity"))
    for value in candidates:
        normalized = str(value or "").lower()
        if normalized in {"critical", "high", "medium", "moderate", "low"}:
            return "medium" if normalized == "moderate" else normalized
    return "unknown"


def fixed_version(advisory: dict, ecosystem: str, package_name: str) -> str | None:
    fixes = []
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != ecosystem or package.get("name") != package_name:
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                if event.get("fixed"):
                    fixes.append(str(event["fixed"]))
    return fixes[-1] if fixes else None


async def query_osv(
    source_items: list[tuple[tuple[str, str], InstalledPackage]], ecosystem: str
) -> tuple[list[dict], dict[str, dict]]:
    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            for start in range(0, len(source_items), 1000):
                batch = source_items[start : start + 1000]
                queries = [
                    {
                        "version": version,
                        "package": {"name": name, "ecosystem": ecosystem},
                    }
                    for (name, version), _package in batch
                ]
                response = await client.post(
                    "https://api.osv.dev/v1/querybatch",
                    json={"queries": queries},
                )
                response.raise_for_status()
                batch_results = response.json().get("results", [])
                if len(batch_results) != len(batch):
                    raise HTTPException(
                        status.HTTP_502_BAD_GATEWAY,
                        "OSV returned an incomplete batch; scan was not saved",
                    )
                for query, result in zip(queries, batch_results, strict=True):
                    while result.get("next_page_token"):
                        page = await client.post(
                            "https://api.osv.dev/v1/query",
                            json={**query, "page_token": result["next_page_token"]},
                        )
                        page.raise_for_status()
                        page_result = page.json()
                        result.setdefault("vulns", []).extend(page_result.get("vulns", []))
                        result["next_page_token"] = page_result.get("next_page_token")
                results.extend(batch_results)
            advisory_ids = {
                str(item["id"])
                for result in results
                for item in result.get("vulns", [])
                if item.get("id")
            }
            semaphore = asyncio.Semaphore(10)

            async def fetch_advisory(advisory_id: str) -> tuple[str, dict]:
                async with semaphore:
                    response = await client.get(
                        f"https://api.osv.dev/v1/vulns/{quote(advisory_id, safe='')}"
                    )
                    response.raise_for_status()
                    return advisory_id, response.json()

            advisories = dict(
                await asyncio.gather(*(fetch_advisory(item) for item in advisory_ids))
            )
            return results, advisories
    except httpx.HTTPError as error:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "OSV vulnerability service request failed"
        ) from error


@router.get("", response_model=list[FindingView])
async def list_findings(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[VulnerabilityFinding]:
    return list(
        await database.scalars(
            select(VulnerabilityFinding).order_by(VulnerabilityFinding.last_seen_at.desc())
        )
    )


@router.post("/hosts/{host_id}/scan", response_model=list[FindingView])
async def scan_host(
    host_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> list[VulnerabilityFinding]:
    host = await database.get(DiscoveredHost, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "discovered host not found")
    cpes = list(
        dict.fromkeys(
            item.get("cpe") for item in json.loads(host.service_evidence or "[]") if item.get("cpe")
        )
    )[:5]
    if not cpes:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "inspect ports first; no exact CPE evidence was detected",
        )
    settings = get_settings()
    headers = {"User-Agent": f"sentinel-home/{settings.sentinel_version}"}
    if settings.nvd_api_key and settings.nvd_api_key.get_secret_value().strip():
        headers["apiKey"] = settings.nvd_api_key.get_secret_value().strip()
    found = []
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        for index, cpe in enumerate(cpes):
            if index and "apiKey" not in headers:
                await asyncio.sleep(6)
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "cpeName": cpe,
                    "isVulnerable": "",
                    "noRejected": "",
                    "resultsPerPage": 100,
                },
                headers=headers,
            )
            response.raise_for_status()
            for wrapper in response.json().get("vulnerabilities", []):
                cve = wrapper.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                item = await database.scalar(
                    select(VulnerabilityFinding).where(
                        VulnerabilityFinding.address == host.address,
                        VulnerabilityFinding.cve_id == cve_id,
                        VulnerabilityFinding.detection_method == "nvd-cpe",
                    )
                )
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "No English description available.",
                )
                severity, score = cvss(cve)
                now = datetime.now(UTC)
                if item is None:
                    item = VulnerabilityFinding(
                        device_id=host.device_id,
                        address=host.address,
                        cve_id=cve_id,
                        title=cve_id,
                        description=description,
                        severity=severity,
                        cvss_score=score,
                        known_exploited=bool(cve.get("cisaExploitAdd")),
                        required_action=cve.get("cisaRequiredAction"),
                        action_due=cve.get("cisaActionDue"),
                        cpe=cpe,
                        status="open",
                        detection_method="nvd-cpe",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    database.add(item)
                else:
                    item.last_seen_at = now
                    item.known_exploited = bool(cve.get("cisaExploitAdd"))
                    item.required_action = cve.get("cisaRequiredAction")
                    item.action_due = cve.get("cisaActionDue")
                found.append(item)
    await database.commit()
    return found


@router.post("/agents/{agent_id}/scan", response_model=list[FindingView])
async def scan_agent_packages(
    agent_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> list[VulnerabilityFinding]:
    agent = await database.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    ecosystem = osv_ecosystem(agent.os_name, agent.os_version)
    if ecosystem is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "package matching currently supports identified Debian and Ubuntu agents",
        )
    packages = list(
        await database.scalars(
            select(InstalledPackage)
            .where(
                InstalledPackage.agent_id == agent.id,
                InstalledPackage.source_name.is_not(None),
                InstalledPackage.source_version.is_not(None),
            )
            .order_by(InstalledPackage.source_name)
        )
    )
    sources: dict[tuple[str, str], InstalledPackage] = {}
    for package in packages:
        sources.setdefault(
            (package.source_name or package.name, package.source_version or package.version),
            package,
        )
    if not sources:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "update the agent to v0.3.0 and wait for its package inventory",
        )
    source_items = list(sources.items())
    results, advisories = await query_osv(source_items, ecosystem)
    address = await database.scalar(
        select(DeviceAddress.address).where(DeviceAddress.device_id == agent.device_id).limit(1)
    )
    address = address or str(agent.device_id)
    now, found = datetime.now(UTC), []
    for ((source_name, source_version), _package), result in zip(
        source_items, results, strict=True
    ):
        for match in result.get("vulns", []):
            advisory = advisories.get(match.get("id"), {})
            aliases = [item for item in advisory.get("aliases", []) if str(item).startswith("CVE-")]
            finding_id = str(aliases[0] if aliases else advisory.get("id", ""))[:30]
            if not finding_id:
                continue
            item = await database.scalar(
                select(VulnerabilityFinding).where(
                    VulnerabilityFinding.address == address,
                    VulnerabilityFinding.cve_id == finding_id,
                    VulnerabilityFinding.detection_method == "osv-agent-package",
                )
            )
            fixed = fixed_version(advisory, ecosystem, source_name)
            action = (
                f"Upgrade {source_name} from {source_version} to {fixed} or later."
                if fixed
                else f"Review the vendor advisory for {source_name}; no fixed version is listed."
            )
            values = {
                "device_id": agent.device_id,
                "title": str(advisory.get("summary") or finding_id)[:300],
                "description": str(
                    advisory.get("details")
                    or advisory.get("summary")
                    or "No description available."
                ),
                "severity": osv_severity(advisory),
                "cpe": f"package:{ecosystem}/{source_name}@{source_version}"[:500],
                "required_action": action,
                "affected_package": source_name,
                "installed_version": source_version,
                "fixed_version": fixed,
                "detection_method": "osv-agent-package",
                "last_seen_at": now,
            }
            if item is None:
                item = VulnerabilityFinding(
                    address=address,
                    cve_id=finding_id,
                    status="open",
                    first_seen_at=now,
                    known_exploited=False,
                    **values,
                )
                database.add(item)
            else:
                for key, value in values.items():
                    setattr(item, key, value)
            found.append(item)
    seen = {item.cve_id for item in found}
    previous = list(
        await database.scalars(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.device_id == agent.device_id,
                VulnerabilityFinding.detection_method == "osv-agent-package",
                VulnerabilityFinding.status.in_(("open", "investigating")),
            )
        )
    )
    for item in previous:
        if item.cve_id not in seen:
            item.status = "resolved"
    await database.commit()
    return found


@router.put("/{finding_id}", response_model=FindingView)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> VulnerabilityFinding:
    finding = await database.get(VulnerabilityFinding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability finding not found")
    finding.status = payload.status
    finding.user_notes = payload.user_notes.strip() if payload.user_notes else None
    await database.commit()
    return finding
