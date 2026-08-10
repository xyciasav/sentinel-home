import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session
from sentinel.database import get_session
from sentinel.models import Device, Session, User, VulnerabilityFinding

router = APIRouter(prefix="/api/v1/actions", tags=["action center"])


class ActionItemView(BaseModel):
    finding_id: uuid.UUID
    cve_id: str
    title: str
    severity: str
    cvss_score: str | None
    known_exploited: bool
    required_action: str | None
    action_due: str | None
    finding_status: str
    address: str
    device_name: str | None
    device_criticality: str | None
    automation_ready: bool
    automation_blocker: str
    priority: int
    affected_package: str | None
    installed_version: str | None
    fixed_version: str | None
    detection_method: str | None


def priority(finding: VulnerabilityFinding, criticality: str | None) -> int:
    score = {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(finding.severity, 5)
    if finding.known_exploited:
        score += 50
    if criticality in {"high", "critical"}:
        score += 10
    return min(score, 100)


@router.get("", response_model=list[ActionItemView])
async def list_actions(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[ActionItemView]:
    rows = (
        await database.execute(
            select(VulnerabilityFinding, Device)
            .outerjoin(Device, Device.id == VulnerabilityFinding.device_id)
            .where(VulnerabilityFinding.status.in_(("open", "investigating")))
        )
    ).all()
    items = [
        ActionItemView(
            finding_id=finding.id,
            cve_id=finding.cve_id,
            title=finding.title,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            known_exploited=finding.known_exploited,
            required_action=finding.required_action,
            action_due=finding.action_due,
            finding_status=finding.status,
            address=finding.address,
            device_name=device.display_name if device else None,
            device_criticality=device.criticality if device else None,
            automation_ready=False,
            automation_blocker=(
                "Package evidence is complete. A signed, approval-gated agent command protocol "
                "must be enabled before a playbook can run."
                if finding.affected_package and finding.fixed_version
                else "Install or update the Linux agent and collect the exact package, installed "
                "version, and fixed version before a playbook can be approved."
            ),
            priority=priority(finding, device.criticality if device else None),
            affected_package=finding.affected_package,
            installed_version=finding.installed_version,
            fixed_version=finding.fixed_version,
            detection_method=finding.detection_method,
        )
        for finding, device in rows
    ]
    return sorted(items, key=lambda item: (-item.priority, item.cve_id, item.address))
