import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session
from sentinel.database import get_session
from sentinel.models import (
    Incident,
    MonitorResult,
    NetworkChange,
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
            .where(VulnerabilityFinding.status.in_(("open", "investigating")))
            .group_by(VulnerabilityFinding.severity)
        )
    ).all()
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
    )
