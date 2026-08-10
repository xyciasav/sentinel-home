import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
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
    cpe: str
    status: str
    first_seen_at: datetime
    last_seen_at: datetime


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
                        cpe=cpe,
                        status="open",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    database.add(item)
                else:
                    item.last_seen_at = now
                found.append(item)
    await database.commit()
    return found
