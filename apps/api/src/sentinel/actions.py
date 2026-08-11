import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    AuditEvent,
    Device,
    RemediationPlan,
    Session,
    User,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/api/v1/actions", tags=["action center"])


class RemediationPlanView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    agent_id: uuid.UUID
    package_name: str
    installed_version: str
    target_version: str
    operation: str
    status: str
    created_at: datetime
    approved_at: datetime | None


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
    plan: RemediationPlanView | None


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
            select(VulnerabilityFinding, Device, Agent, RemediationPlan)
            .outerjoin(Device, Device.id == VulnerabilityFinding.device_id)
            .outerjoin(Agent, (Agent.device_id == Device.id) & Agent.revoked_at.is_(None))
            .outerjoin(RemediationPlan, RemediationPlan.finding_id == VulnerabilityFinding.id)
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
            automation_ready=bool(
                agent
                and finding.affected_package
                and finding.installed_version
                and finding.fixed_version
            ),
            automation_blocker=(
                "Ready to build an exact, approval-gated package upgrade plan."
                if agent
                and finding.affected_package
                and finding.installed_version
                and finding.fixed_version
                else "Install or update the Linux agent and collect the exact package, installed "
                "version, and fixed version before a playbook can be approved."
            ),
            priority=priority(finding, device.criticality if device else None),
            affected_package=finding.affected_package,
            installed_version=finding.installed_version,
            fixed_version=finding.fixed_version,
            detection_method=finding.detection_method,
            plan=plan,
        )
        for finding, device, agent, plan in rows
    ]
    return sorted(items, key=lambda item: (-item.priority, item.cve_id, item.address))


@router.post("/{finding_id}/plans", response_model=RemediationPlanView, status_code=201)
async def build_plan(
    finding_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RemediationPlan:
    existing = await database.scalar(
        select(RemediationPlan).where(RemediationPlan.finding_id == finding_id)
    )
    if existing is not None:
        return existing
    finding = await database.get(VulnerabilityFinding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability finding not found")
    if not all(
        (
            finding.device_id,
            finding.affected_package,
            finding.installed_version,
            finding.fixed_version,
        )
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "exact package, installed version, fixed version, and enrolled device are required",
        )
    agent = await database.scalar(
        select(Agent).where(Agent.device_id == finding.device_id, Agent.revoked_at.is_(None))
    )
    if agent is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "active Linux agent required")
    plan = RemediationPlan(
        finding_id=finding.id,
        agent_id=agent.id,
        package_name=finding.affected_package,
        installed_version=finding.installed_version,
        target_version=finding.fixed_version,
        created_by=auth[0].id,
        created_at=datetime.now(UTC),
    )
    database.add(plan)
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="remediation.plan.create",
            target_type="vulnerability_finding",
            target_id=str(finding.id),
        )
    )
    await database.commit()
    await database.refresh(plan)
    return plan


@router.post("/plans/{plan_id}/approve", response_model=RemediationPlanView)
async def approve_plan(
    plan_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RemediationPlan:
    plan = await database.scalar(
        select(RemediationPlan).where(RemediationPlan.id == plan_id).with_for_update()
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation plan not found")
    if plan.status != "draft":
        raise HTTPException(status.HTTP_409_CONFLICT, "only draft plans can be approved")
    plan.status = "approved"
    plan.approved_by = auth[0].id
    plan.approved_at = datetime.now(UTC)
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="remediation.plan.approve",
            target_type="remediation_plan",
            target_id=str(plan.id),
        )
    )
    await database.commit()
    await database.refresh(plan)
    return plan
