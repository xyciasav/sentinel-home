import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.config import get_settings
from sentinel.database import get_session
from sentinel.models import Incident, NotificationDelivery, Session, User

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
    if not settings.email_alerts_configured:
        delivery.error = "Resend email settings are not configured"
        return delivery
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key.get_secret_value()}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": f"sentinel-{delivery.id}",
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
            select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(200)
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
