import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.config import get_settings
from sentinel.database import get_session
from sentinel.models import AuditEvent, Device, Incident, NotificationDelivery, Session, User

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


class NotificationView(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID | None
    kind: str
    recipient: str | None
    subject: str
    status: str
    error: str | None
    created_at: datetime
    sent_at: datetime | None


class DismissInput(BaseModel):
    ids: list[uuid.UUID] = Field(min_length=1, max_length=200)


class MuteInput(BaseModel):
    minutes: int = Field(ge=0, le=10_080)
    reason: str | None = Field(default=None, max_length=300)


class MuteView(BaseModel):
    device_id: uuid.UUID
    alerts_muted_until: datetime | None
    alert_mute_reason: str | None


async def send_email(
    database: AsyncSession,
    kind: str,
    subject: str,
    text: str,
    incident: Incident | None = None,
) -> NotificationDelivery:
    settings = get_settings()
    delivery = NotificationDelivery(
        incident_id=incident.id if incident else None,
        kind=kind,
        recipient=settings.alert_to_email,
        subject=subject,
        status="skipped",
    )
    database.add(delivery)
    await database.flush()
    if incident and incident.device_id:
        device = await database.get(Device, incident.device_id)
        if device and device.alerts_muted_until and device.alerts_muted_until > datetime.now(UTC):
            delivery.status = "muted"
            delivery.error = device.alert_mute_reason or "device alerts are muted"
            return delivery
    if not settings.email_alerts_configured:
        delivery.error = "Resend email settings are not configured"
        return delivery
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key.get_secret_value().strip()}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": f"sentinel-{delivery.id}",
                    "User-Agent": f"sentinel-home/{settings.sentinel_version}",
                },
                json={
                    "from": settings.alert_from_email,
                    "to": [settings.alert_to_email],
                    "subject": subject,
                    "text": text,
                },
            )
            response.raise_for_status()
            delivery.provider_id = response.json().get("id")
            delivery.status = "sent"
            delivery.sent_at = datetime.now(UTC)
    except httpx.HTTPStatusError as error:
        delivery.status = "failed"
        try:
            detail = error.response.json().get("message") or error.response.text
        except ValueError:
            detail = error.response.text
        delivery.error = f"Resend HTTP {error.response.status_code}: {detail}"[:500]
    except (httpx.HTTPError, ValueError) as error:
        delivery.status = "failed"
        delivery.error = str(error)[:500]
    return delivery


@router.get("", response_model=list[NotificationView])
async def list_notifications(
    database: Annotated[AsyncSession, Depends(get_session)],
    _authenticated: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[NotificationDelivery]:
    return list(
        await database.scalars(
            select(NotificationDelivery)
            .where(NotificationDelivery.dismissed_at.is_(None))
            .order_by(NotificationDelivery.created_at.desc())
            .limit(200)
        )
    )


@router.post("/test", response_model=NotificationView)
async def test_notification(
    database: Annotated[AsyncSession, Depends(get_session)],
    authenticated: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> NotificationDelivery:
    delivery = await send_email(
        database,
        "test",
        "[Test] Sentinel Home email notifications",
        f"Email notifications were tested by {authenticated[0].username}. Sentinel Home is ready.",
    )
    await database.commit()
    return delivery


@router.post("/dismiss", status_code=204)
async def dismiss_notifications(
    payload: DismissInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    now = datetime.now(UTC)
    await database.execute(
        update(NotificationDelivery)
        .where(NotificationDelivery.id.in_(set(payload.ids)))
        .values(dismissed_at=now)
    )
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="notification.dismiss.bulk",
            target_type="notification_delivery",
            target_id=f"{len(set(payload.ids))} selected",
        )
    )
    await database.commit()


@router.post("/devices/{device_id}/mute", response_model=MuteView)
async def mute_device_alerts(
    device_id: uuid.UUID,
    payload: MuteInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> MuteView:
    device = await database.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    device.alerts_muted_until = (
        datetime.now(UTC) + timedelta(minutes=payload.minutes) if payload.minutes else None
    )
    device.alert_mute_reason = (
        payload.reason.strip() if payload.minutes and payload.reason else None
    )
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="device.alerts.mute" if payload.minutes else "device.alerts.unmute",
            target_type="device",
            target_id=str(device.id),
        )
    )
    await database.commit()
    return MuteView(
        device_id=device.id,
        alerts_muted_until=device.alerts_muted_until,
        alert_mute_reason=device.alert_mute_reason,
    )
