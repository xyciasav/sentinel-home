import csv
import io
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session
from sentinel.database import get_session
from sentinel.models import (
    Agent,
    ContainerEvent,
    Device,
    Incident,
    MonitorResult,
    NetworkChange,
    RemediationPlan,
    ServiceMonitor,
    Session,
    StorageFinding,
    User,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def percentage(successes: int, total: int) -> float | None:
    return round(successes * 100 / total, 2) if total else None


class WindowView(BaseModel):
    checks: int
    successful: int
    uptime_percent: float | None
    average_response_ms: int | None


class ServiceView(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    checks: int
    uptime_percent: float | None
    average_response_ms: int | None


class DeviceSecurityView(BaseModel):
    id: uuid.UUID
    name: str
    criticality: str
    agent_applicable: bool
    agent_version: str | None
    agent_connected: bool
    active_vulnerabilities: int
    critical_high: int
    known_exploited: int
    remediation_failed: int


class ReportView(BaseModel):
    generated_at: datetime
    last_24_hours: WindowView
    last_7_days: WindowView
    services: list[ServiceView]
    open_incidents: int
    incidents_7_days: int
    network_changes_7_days: int
    active_vulnerabilities: dict[str, int]
    known_exploited: int
    storage_recommendations: int
    storage_flagged_bytes: int
    agents_total: int
    agents_connected: int
    agents_current: int
    package_vulnerabilities: int
    remediation_status: dict[str, int]
    devices: list[DeviceSecurityView]


class DailyTrendView(BaseModel):
    date: str
    checks: int
    successful: int
    uptime_percent: float | None
    average_response_ms: int | None
    incidents: int
    expected_incidents: int
    network_changes: int
    container_alerts: int


class HistoricalReportView(BaseModel):
    generated_at: datetime
    days: int
    start_at: datetime
    end_at: datetime
    summary: WindowView
    incidents: int
    expected_incidents: int
    network_changes: int
    container_alerts: int
    daily: list[DailyTrendView]
    services: list[ServiceView]


async def historical_report(database: AsyncSession, days: int) -> HistoricalReportView:
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    monitor_rows = (
        await database.execute(
            select(
                func.date(MonitorResult.checked_at),
                func.count(MonitorResult.id),
                func.coalesce(func.sum(case((MonitorResult.success.is_(True), 1), else_=0)), 0),
                func.avg(MonitorResult.response_ms),
            )
            .where(MonitorResult.checked_at >= since)
            .group_by(func.date(MonitorResult.checked_at))
        )
    ).all()
    incident_rows = (
        await database.execute(
            select(
                func.date(Incident.started_at),
                func.count(Incident.id),
                func.coalesce(func.sum(case((Incident.expected.is_(True), 1), else_=0)), 0),
            )
            .where(Incident.started_at >= since)
            .group_by(func.date(Incident.started_at))
        )
    ).all()
    change_rows = (
        await database.execute(
            select(func.date(NetworkChange.detected_at), func.count(NetworkChange.id))
            .where(NetworkChange.detected_at >= since)
            .group_by(func.date(NetworkChange.detected_at))
        )
    ).all()
    container_rows = (
        await database.execute(
            select(func.date(ContainerEvent.occurred_at), func.count(ContainerEvent.id))
            .where(ContainerEvent.occurred_at >= since)
            .group_by(func.date(ContainerEvent.occurred_at))
        )
    ).all()
    monitors = {str(row[0]): row for row in monitor_rows}
    incidents = {str(row[0]): row for row in incident_rows}
    changes = {str(row[0]): int(row[1]) for row in change_rows}
    containers = {str(row[0]): int(row[1]) for row in container_rows}
    daily = []
    for offset in range(days - 1, -1, -1):
        key = (now - timedelta(days=offset)).date().isoformat()
        monitor = monitors.get(key)
        incident = incidents.get(key)
        checks, successful = (int(monitor[1]), int(monitor[2])) if monitor else (0, 0)
        daily.append(
            DailyTrendView(
                date=key,
                checks=checks,
                successful=successful,
                uptime_percent=percentage(successful, checks),
                average_response_ms=round(float(monitor[3]))
                if monitor and monitor[3] is not None
                else None,
                incidents=int(incident[1]) if incident else 0,
                expected_incidents=int(incident[2]) if incident else 0,
                network_changes=changes.get(key, 0),
                container_alerts=containers.get(key, 0),
            )
        )
    service_rows = (
        await database.execute(
            select(
                ServiceMonitor.id,
                ServiceMonitor.name,
                ServiceMonitor.status,
                func.count(MonitorResult.id),
                func.coalesce(func.sum(case((MonitorResult.success.is_(True), 1), else_=0)), 0),
                func.avg(MonitorResult.response_ms),
            )
            .outerjoin(
                MonitorResult,
                and_(
                    MonitorResult.monitor_id == ServiceMonitor.id, MonitorResult.checked_at >= since
                ),
            )
            .where(ServiceMonitor.enabled.is_(True))
            .group_by(ServiceMonitor.id)
            .order_by(ServiceMonitor.name)
        )
    ).all()
    services = [
        ServiceView(
            id=row[0],
            name=row[1],
            status=row[2],
            checks=int(row[3]),
            uptime_percent=percentage(int(row[4]), int(row[3])),
            average_response_ms=round(float(row[5])) if row[5] is not None else None,
        )
        for row in service_rows
    ]
    return HistoricalReportView(
        generated_at=now,
        days=days,
        start_at=since,
        end_at=now,
        summary=await monitor_window(database, since),
        incidents=sum(item.incidents for item in daily),
        expected_incidents=sum(item.expected_incidents for item in daily),
        network_changes=sum(item.network_changes for item in daily),
        container_alerts=sum(item.container_alerts for item in daily),
        daily=daily,
        services=services,
    )


@router.get("/history", response_model=HistoricalReportView)
async def history_report(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
    days: Annotated[int, Query(ge=7, le=90)] = 30,
) -> HistoricalReportView:
    return await historical_report(database, days)


@router.get("/history.csv")
async def history_csv(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
    days: Annotated[int, Query(ge=7, le=90)] = 30,
) -> StreamingResponse:
    report = await historical_report(database, days)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "date",
            "checks",
            "successful",
            "uptime_percent",
            "average_response_ms",
            "incidents",
            "expected_incidents",
            "network_changes",
            "container_alerts",
        ]
    )
    for item in report.daily:
        writer.writerow(
            [
                item.date,
                item.checks,
                item.successful,
                item.uptime_percent or "",
                item.average_response_ms or "",
                item.incidents,
                item.expected_incidents,
                item.network_changes,
                item.container_alerts,
            ]
        )
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="sentinel-history-{days}d.csv"'},
    )


async def monitor_window(database: AsyncSession, since: datetime) -> WindowView:
    row = (
        await database.execute(
            select(
                func.count(MonitorResult.id),
                func.coalesce(func.sum(case((MonitorResult.success.is_(True), 1), else_=0)), 0),
                func.avg(MonitorResult.response_ms),
            ).where(MonitorResult.checked_at >= since)
        )
    ).one()
    checks, successful, average = int(row[0]), int(row[1]), row[2]
    return WindowView(
        checks=checks,
        successful=successful,
        uptime_percent=percentage(successful, checks),
        average_response_ms=round(float(average)) if average is not None else None,
    )


@router.get("/overview", response_model=ReportView)
async def overview_report(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> ReportView:
    now = datetime.now(UTC)
    day_ago, week_ago = now - timedelta(days=1), now - timedelta(days=7)
    day, week = await monitor_window(database, day_ago), await monitor_window(database, week_ago)
    service_rows = (
        await database.execute(
            select(
                ServiceMonitor.id,
                ServiceMonitor.name,
                ServiceMonitor.status,
                func.count(MonitorResult.id),
                func.coalesce(func.sum(case((MonitorResult.success.is_(True), 1), else_=0)), 0),
                func.avg(MonitorResult.response_ms),
            )
            .outerjoin(
                MonitorResult,
                and_(
                    MonitorResult.monitor_id == ServiceMonitor.id,
                    MonitorResult.checked_at >= day_ago,
                ),
            )
            .where(ServiceMonitor.enabled.is_(True))
            .group_by(ServiceMonitor.id)
            .order_by(ServiceMonitor.name)
        )
    ).all()
    services = [
        ServiceView(
            id=row[0],
            name=row[1],
            status=row[2],
            checks=int(row[3]),
            uptime_percent=percentage(int(row[4]), int(row[3])),
            average_response_ms=round(float(row[5])) if row[5] is not None else None,
        )
        for row in service_rows
    ]
    vulnerability_rows = (
        await database.execute(
            select(VulnerabilityFinding.severity, func.count(VulnerabilityFinding.id))
            .where(
                VulnerabilityFinding.status.in_(("open", "investigating")),
                or_(
                    VulnerabilityFinding.severity != "unknown",
                    VulnerabilityFinding.known_exploited.is_(True),
                ),
            )
            .group_by(VulnerabilityFinding.severity)
        )
    ).all()
    agents = list(await database.scalars(select(Agent).where(Agent.revoked_at.is_(None))))
    remediation_rows = (
        await database.execute(
            select(RemediationPlan.status, func.count(RemediationPlan.id)).group_by(
                RemediationPlan.status
            )
        )
    ).all()
    device_rows = (
        await database.execute(
            select(Device, Agent)
            .outerjoin(Agent, (Agent.device_id == Device.id) & Agent.revoked_at.is_(None))
            .order_by(Device.display_name)
        )
    ).all()
    device_security = []
    for device, agent in device_rows:
        active_filter = (
            VulnerabilityFinding.device_id == device.id,
            VulnerabilityFinding.status.in_(("open", "investigating")),
            or_(
                VulnerabilityFinding.severity != "unknown",
                VulnerabilityFinding.known_exploited.is_(True),
            ),
        )
        device_security.append(
            DeviceSecurityView(
                id=device.id,
                name=device.display_name,
                criticality=device.criticality,
                agent_applicable=device.agent_applicable,
                agent_version=agent.version if agent else None,
                agent_connected=bool(
                    agent
                    and agent.last_heartbeat_at
                    and agent.last_heartbeat_at >= now - timedelta(seconds=45)
                ),
                active_vulnerabilities=int(
                    await database.scalar(
                        select(func.count(VulnerabilityFinding.id)).where(*active_filter)
                    )
                    or 0
                ),
                critical_high=int(
                    await database.scalar(
                        select(func.count(VulnerabilityFinding.id)).where(
                            *active_filter,
                            VulnerabilityFinding.severity.in_(("critical", "high")),
                        )
                    )
                    or 0
                ),
                known_exploited=int(
                    await database.scalar(
                        select(func.count(VulnerabilityFinding.id)).where(
                            *active_filter, VulnerabilityFinding.known_exploited.is_(True)
                        )
                    )
                    or 0
                ),
                remediation_failed=int(
                    await database.scalar(
                        select(func.count(RemediationPlan.id))
                        .join(
                            VulnerabilityFinding,
                            VulnerabilityFinding.id == RemediationPlan.finding_id,
                        )
                        .where(
                            VulnerabilityFinding.device_id == device.id,
                            RemediationPlan.status == "failed",
                        )
                    )
                    or 0
                ),
            )
        )
    scalar = database.scalar
    return ReportView(
        generated_at=now,
        last_24_hours=day,
        last_7_days=week,
        services=services,
        open_incidents=int(
            await scalar(select(func.count(Incident.id)).where(Incident.status == "open")) or 0
        ),
        incidents_7_days=int(
            await scalar(select(func.count(Incident.id)).where(Incident.started_at >= week_ago))
            or 0
        ),
        network_changes_7_days=int(
            await scalar(
                select(func.count(NetworkChange.id)).where(NetworkChange.detected_at >= week_ago)
            )
            or 0
        ),
        active_vulnerabilities={str(row[0]): int(row[1]) for row in vulnerability_rows},
        known_exploited=int(
            await scalar(
                select(func.count(VulnerabilityFinding.id)).where(
                    VulnerabilityFinding.status.in_(("open", "investigating")),
                    VulnerabilityFinding.known_exploited.is_(True),
                )
            )
            or 0
        ),
        storage_recommendations=int(await scalar(select(func.count(StorageFinding.id))) or 0),
        storage_flagged_bytes=int(
            await scalar(select(func.coalesce(func.sum(StorageFinding.size_bytes), 0))) or 0
        ),
        agents_total=len(agents),
        agents_connected=sum(
            bool(item.last_heartbeat_at and item.last_heartbeat_at >= now - timedelta(seconds=45))
            for item in agents
        ),
        agents_current=sum(
            item.version == "0.6.2" and item.executor_version == "0.3.3" for item in agents
        ),
        package_vulnerabilities=int(
            await scalar(
                select(func.count(VulnerabilityFinding.id)).where(
                    VulnerabilityFinding.status.in_(("open", "investigating")),
                    VulnerabilityFinding.detection_method == "osv-agent-package",
                )
            )
            or 0
        ),
        remediation_status={str(row[0]): int(row[1]) for row in remediation_rows},
        devices=device_security,
    )
