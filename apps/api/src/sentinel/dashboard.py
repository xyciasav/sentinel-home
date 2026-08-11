from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    ApplicationEvent,
    ApplicationIntegration,
    ContainerEvent,
    Device,
    Incident,
    NetworkIdentityEvent,
    ServiceMonitor,
    Session,
    User,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


class AttentionItem(BaseModel):
    source: str
    severity: str
    title: str
    detail: str
    occurred_at: datetime
    acknowledged: bool


class DashboardView(BaseModel):
    generated_at: datetime
    devices_total: int
    devices_online: int
    appliance_devices: int
    services_total: int
    services_up: int
    open_incidents: int
    agents_expected: int
    agents_connected: int
    applications_total: int
    applications_healthy: int
    vulnerabilities_active: int
    vulnerabilities_critical_high: int
    known_exploited: int
    network_alerts_open: int
    container_alerts_open: int
    application_alerts_open: int
    attention: list[AttentionItem]


@router.get("", response_model=DashboardView)
async def dashboard(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> DashboardView:
    now = datetime.now(UTC)
    scalar = database.scalar
    agents = list(await database.scalars(select(Agent).where(Agent.revoked_at.is_(None))))
    incidents = list(
        await database.scalars(select(Incident).order_by(Incident.started_at.desc()).limit(10))
    )
    app_events = list(
        await database.scalars(
            select(ApplicationEvent).order_by(ApplicationEvent.occurred_at.desc()).limit(20)
        )
    )
    container_events = list(
        await database.scalars(
            select(ContainerEvent).order_by(ContainerEvent.occurred_at.desc()).limit(20)
        )
    )
    network_events = list(
        await database.scalars(
            select(NetworkIdentityEvent).order_by(NetworkIdentityEvent.occurred_at.desc()).limit(20)
        )
    )
    attention = [
        AttentionItem(
            source="incident",
            severity=item.severity,
            title=item.title,
            detail=item.summary,
            occurred_at=item.started_at,
            acknowledged=item.acknowledged_at is not None,
        )
        for item in incidents
    ]
    attention += [
        AttentionItem(
            source="application",
            severity=item.severity,
            title=item.kind.replace("_", " ").title(),
            detail=item.message,
            occurred_at=item.occurred_at,
            acknowledged=item.acknowledged_at is not None,
        )
        for item in app_events
    ]
    attention += [
        AttentionItem(
            source="container",
            severity=item.severity,
            title=f"{item.container_name}: {item.kind.replace('_', ' ')}",
            detail=item.message,
            occurred_at=item.occurred_at,
            acknowledged=item.acknowledged_at is not None,
        )
        for item in container_events
    ]
    attention += [
        AttentionItem(
            source="network",
            severity="medium" if item.kind == "identity_seen" else "low",
            title=f"{item.name}: {item.kind.replace('_', ' ')}",
            detail=item.new_value or "Identity change",
            occurred_at=item.occurred_at,
            acknowledged=item.acknowledged_at is not None,
        )
        for item in network_events
    ]
    attention.sort(key=lambda item: item.occurred_at, reverse=True)
    active_findings = (VulnerabilityFinding.status.in_(("open", "investigating")),)
    return DashboardView(
        generated_at=now,
        devices_total=int(await scalar(select(func.count(Device.id))) or 0),
        devices_online=int(
            await scalar(select(func.count(Device.id)).where(Device.status == "online")) or 0
        ),
        appliance_devices=int(
            await scalar(select(func.count(Device.id)).where(Device.agent_applicable.is_(False)))
            or 0
        ),
        services_total=int(
            await scalar(
                select(func.count(ServiceMonitor.id)).where(ServiceMonitor.enabled.is_(True))
            )
            or 0
        ),
        services_up=int(
            await scalar(
                select(func.count(ServiceMonitor.id)).where(
                    ServiceMonitor.enabled.is_(True), ServiceMonitor.status == "up"
                )
            )
            or 0
        ),
        open_incidents=int(
            await scalar(select(func.count(Incident.id)).where(Incident.status == "open")) or 0
        ),
        agents_expected=int(
            await scalar(select(func.count(Device.id)).where(Device.agent_applicable.is_(True)))
            or 0
        ),
        agents_connected=sum(
            bool(item.last_heartbeat_at and item.last_heartbeat_at >= now - timedelta(seconds=45))
            for item in agents
        ),
        applications_total=int(await scalar(select(func.count(ApplicationIntegration.id))) or 0),
        applications_healthy=int(
            await scalar(
                select(func.count(ApplicationIntegration.id)).where(
                    ApplicationIntegration.last_sync_status == "healthy"
                )
            )
            or 0
        ),
        vulnerabilities_active=int(
            await scalar(select(func.count(VulnerabilityFinding.id)).where(*active_findings)) or 0
        ),
        vulnerabilities_critical_high=int(
            await scalar(
                select(func.count(VulnerabilityFinding.id)).where(
                    *active_findings, VulnerabilityFinding.severity.in_(("critical", "high"))
                )
            )
            or 0
        ),
        known_exploited=int(
            await scalar(
                select(func.count(VulnerabilityFinding.id)).where(
                    *active_findings, VulnerabilityFinding.known_exploited.is_(True)
                )
            )
            or 0
        ),
        network_alerts_open=int(
            await scalar(
                select(func.count(NetworkIdentityEvent.id)).where(
                    NetworkIdentityEvent.acknowledged_at.is_(None)
                )
            )
            or 0
        ),
        container_alerts_open=int(
            await scalar(
                select(func.count(ContainerEvent.id)).where(
                    ContainerEvent.acknowledged_at.is_(None)
                )
            )
            or 0
        ),
        application_alerts_open=int(
            await scalar(
                select(func.count(ApplicationEvent.id)).where(
                    ApplicationEvent.acknowledged_at.is_(None)
                )
            )
            or 0
        ),
        attention=attention[:20],
    )
