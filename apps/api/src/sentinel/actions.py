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
    InstalledPackage,
    RemediationPlan,
    Session,
    User,
    VulnerabilityFinding,
)
from sentinel.vulnerabilities import reconcile_package_findings

router = APIRouter(prefix="/api/v1/actions", tags=["action center"])
REQUIRED_EXECUTOR_VERSION = "0.3.3"


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
    dispatched_at: datetime | None
    completed_at: datetime | None
    result_output: str | None
    result_error: str | None


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


def automation_blocker(
    finding: VulnerabilityFinding,
    agent: Agent | None,
    candidate_version: str | None,
    agent_applicable: bool = True,
) -> str:
    if not agent_applicable:
        return (
            "Agent automation is not applicable to this appliance; review the vendor update path."
        )
    if finding.detection_method != "osv-agent-package":
        return (
            "This is a network/service finding, so there is no verified Linux package to upgrade. "
            "Inspect it manually or scan an enrolled agent on this device for package-level "
            "evidence."
        )
    if agent is None:
        return "Install or reconnect the Linux agent for this device before building a playbook."
    if agent.executor_version != REQUIRED_EXECUTOR_VERSION:
        return (
            f"Update or repair the agent executor (required {REQUIRED_EXECUTOR_VERSION}, "
            f"reported {agent.executor_version or 'not installed'})."
        )
    if finding.affected_package and finding.installed_version and not candidate_version:
        return (
            "APT reports no repository upgrade candidate. This is commonly an old-release or "
            "backports package and requires manual replacement or removal."
        )
    return (
        "Collect the exact installed package and vendor fixed version before building a playbook."
    )


@router.get("", response_model=list[ActionItemView])
async def list_actions(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[ActionItemView]:
    await reconcile_package_findings(database)
    rows = (
        await database.execute(
            select(VulnerabilityFinding, Device, Agent, RemediationPlan)
            .outerjoin(Device, Device.id == VulnerabilityFinding.device_id)
            .outerjoin(Agent, (Agent.device_id == Device.id) & Agent.revoked_at.is_(None))
            .outerjoin(RemediationPlan, RemediationPlan.finding_id == VulnerabilityFinding.id)
            .where(VulnerabilityFinding.status.in_(("open", "investigating")))
        )
    ).all()
    items = []
    for finding, device, agent, plan in rows:
        candidate_version = None
        if agent and finding.affected_package and finding.installed_version:
            candidate_version = await database.scalar(
                select(InstalledPackage.candidate_version)
                .where(
                    InstalledPackage.agent_id == agent.id,
                    InstalledPackage.source_name == finding.affected_package,
                    InstalledPackage.source_version == finding.installed_version,
                    InstalledPackage.candidate_version.is_not(None),
                )
                .limit(1)
            )
        ready = bool(
            agent
            and agent.executor_version == REQUIRED_EXECUTOR_VERSION
            and finding.detection_method == "osv-agent-package"
            and finding.affected_package
            and finding.installed_version
            and finding.fixed_version
            and candidate_version
        )
        items.append(
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
                automation_ready=ready,
                automation_blocker=(
                    "Ready to build an exact, approval-gated package upgrade plan."
                    if ready
                    else automation_blocker(
                        finding,
                        agent,
                        candidate_version,
                        device.agent_applicable if device else True,
                    )
                ),
                priority=priority(finding, device.criticality if device else None),
                affected_package=finding.affected_package,
                installed_version=finding.installed_version,
                fixed_version=finding.fixed_version,
                detection_method=finding.detection_method,
                plan=plan,
            )
        )
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
    if finding.detection_method != "osv-agent-package":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "network and service findings cannot be converted into package playbooks",
        )
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
    if agent.executor_version != REQUIRED_EXECUTOR_VERSION:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"agent executor {REQUIRED_EXECUTOR_VERSION} must be installed before building a plan",
        )
    binary_packages = list(
        await database.scalars(
            select(InstalledPackage)
            .where(
                InstalledPackage.agent_id == agent.id,
                InstalledPackage.source_name == finding.affected_package,
                InstalledPackage.source_version == finding.installed_version,
            )
            .order_by(InstalledPackage.name)
        )
    )
    binary_package = next(
        (item for item in binary_packages if item.name == finding.affected_package),
        next((item for item in binary_packages if not item.name.endswith("-dev")), None),
    )
    if binary_package is None or not binary_package.candidate_version:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "APT has no repository upgrade candidate; manually replace or remove this "
            "old-release package",
        )
    plan = RemediationPlan(
        finding_id=finding.id,
        agent_id=agent.id,
        package_name=binary_package.name if binary_package else finding.affected_package,
        installed_version=binary_package.version if binary_package else finding.installed_version,
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


@router.post("/plans/{plan_id}/release", response_model=RemediationPlanView)
async def release_plan(
    plan_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RemediationPlan:
    plan = await database.scalar(
        select(RemediationPlan).where(RemediationPlan.id == plan_id).with_for_update()
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation plan not found")
    if plan.status != "approved":
        raise HTTPException(status.HTTP_409_CONFLICT, "only approved plans can be released")
    agent = await database.get(Agent, plan.agent_id)
    if agent is None or agent.executor_version != REQUIRED_EXECUTOR_VERSION:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"agent executor {REQUIRED_EXECUTOR_VERSION} must be installed before release",
        )
    plan.status = "queued"
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="remediation.plan.release",
            target_type="remediation_plan",
            target_id=str(plan.id),
        )
    )
    await database.commit()
    await database.refresh(plan)
    return plan


async def transition_plan(
    plan_id: uuid.UUID,
    allowed: tuple[str, ...],
    new_status: str,
    action: str,
    database: AsyncSession,
    user: User,
) -> RemediationPlan:
    plan = await database.scalar(
        select(RemediationPlan).where(RemediationPlan.id == plan_id).with_for_update()
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation plan not found")
    if plan.status not in allowed:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"plan in {plan.status} state cannot transition to {new_status}",
        )
    plan.status = new_status
    if new_status == "queued":
        plan.dispatched_at = None
        plan.completed_at = None
        plan.result_output = None
        plan.result_error = None
    database.add(
        AuditEvent(
            actor_user_id=user.id,
            action=action,
            target_type="remediation_plan",
            target_id=str(plan.id),
        )
    )
    await database.commit()
    await database.refresh(plan)
    return plan


@router.post("/plans/{plan_id}/cancel", response_model=RemediationPlanView)
async def cancel_plan(
    plan_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RemediationPlan:
    return await transition_plan(
        plan_id, ("approved", "queued"), "canceled", "remediation.plan.cancel", database, auth[0]
    )


@router.post("/plans/{plan_id}/retry", response_model=RemediationPlanView)
async def retry_plan(
    plan_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RemediationPlan:
    plan = await database.get(RemediationPlan, plan_id)
    agent = await database.get(Agent, plan.agent_id) if plan else None
    if agent is None or agent.executor_version != REQUIRED_EXECUTOR_VERSION:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"repair agent executor {REQUIRED_EXECUTOR_VERSION} before retrying",
        )
    return await transition_plan(
        plan_id, ("failed",), "queued", "remediation.plan.retry", database, auth[0]
    )


@router.post("/plans/{plan_id}/archive", response_model=RemediationPlanView)
async def archive_plan(
    plan_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> RemediationPlan:
    return await transition_plan(
        plan_id,
        ("completed", "failed", "canceled"),
        "archived",
        "remediation.plan.archive",
        database,
        auth[0],
    )
