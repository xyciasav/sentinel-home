import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.config import get_settings
from sentinel.database import get_session
from sentinel.models import DiscoveredHost, Session, User, VulnerabilityFinding

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
