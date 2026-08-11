import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session, get_session_factory
from sentinel.models import ApplicationIntegration, ApplicationSnapshot, AuditEvent, Session, User
from sentinel.security import decrypt_secret, encrypt_secret
from sentinel.sources import safe_base_url

router = APIRouter(prefix="/api/v1/applications", tags=["application insights"])


class ApplicationInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str = Field(pattern=r"^(sonarr|radarr|sabnzbd)$")
    base_url: AnyHttpUrl
    api_key: str = Field(min_length=1, max_length=1000)


class SnapshotView(BaseModel):
    version: str | None
    queue_count: int
    failed_count: int
    item_count: int
    active_count: int
    disk_free_bytes: int | None
    collected_at: datetime


class ApplicationView(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    base_url: str
    enabled: bool
    last_sync_at: datetime | None
    last_sync_status: str
    last_sync_error: str | None
    latest: SnapshotView | None
    history: list[SnapshotView]


async def collect(integration: ApplicationIntegration) -> dict:
    base = integration.base_url.rstrip("/")
    key = decrypt_secret(integration.credential_encrypted)
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        if integration.kind in {"sonarr", "radarr"}:
            headers = {"X-Api-Key": key}
            prefix = f"{base}/api/v3"
            (
                status_response,
                queue_response,
                history_response,
                items_response,
                disk_response,
            ) = await asyncio.gather(
                client.get(f"{prefix}/system/status", headers=headers),
                client.get(f"{prefix}/queue", headers=headers, params={"pageSize": 1}),
                client.get(
                    f"{prefix}/history", headers=headers, params={"pageSize": 1, "eventType": 4}
                ),
                client.get(
                    f"{prefix}/series" if integration.kind == "sonarr" else f"{prefix}/movie",
                    headers=headers,
                ),
                client.get(f"{prefix}/diskspace", headers=headers),
            )
            for response in (
                status_response,
                queue_response,
                history_response,
                items_response,
                disk_response,
            ):
                response.raise_for_status()
            status_data, queue, failed, items, disks = (
                status_response.json(),
                queue_response.json(),
                history_response.json(),
                items_response.json(),
                disk_response.json(),
            )
            return {
                "version": str(status_data.get("version") or "")[:100] or None,
                "queue_count": int(queue.get("totalRecords") or 0),
                "failed_count": int(failed.get("totalRecords") or 0),
                "item_count": len(items),
                "active_count": sum(bool(item.get("monitored")) for item in items),
                "disk_free_bytes": sum(int(item.get("freeSpace") or 0) for item in disks),
            }
        response = await client.get(
            f"{base}/api", params={"mode": "queue", "output": "json", "apikey": key}
        )
        history = await client.get(
            f"{base}/api", params={"mode": "history", "output": "json", "apikey": key, "limit": 50}
        )
        response.raise_for_status()
        history.raise_for_status()
        queue, past = response.json().get("queue", {}), history.json().get("history", {})
        slots, history_slots = queue.get("slots", []), past.get("slots", [])
        return {
            "version": str(queue.get("version") or "")[:100] or None,
            "queue_count": len(slots),
            "failed_count": sum(item.get("status") == "Failed" for item in history_slots),
            "item_count": len(history_slots),
            "active_count": sum(
                item.get("status") in {"Downloading", "Extracting", "Verifying"} for item in slots
            ),
            "disk_free_bytes": int(float(queue.get("diskspace2_norm") or 0) * 1_000_000_000)
            if queue.get("diskspace2_norm")
            else None,
        }


async def sync_application(database: AsyncSession, integration: ApplicationIntegration) -> None:
    try:
        values = await collect(integration)
        database.add(ApplicationSnapshot(integration_id=integration.id, **values))
        integration.last_sync_status = "healthy"
        integration.last_sync_error = None
    except (httpx.HTTPError, ValueError, TypeError) as error:
        integration.last_sync_status = "failed"
        integration.last_sync_error = str(error)[:500]
    integration.last_sync_at = datetime.now(UTC)
    await database.commit()


async def application_view(database: AsyncSession, item: ApplicationIntegration) -> ApplicationView:
    history = list(
        await database.scalars(
            select(ApplicationSnapshot)
            .where(
                ApplicationSnapshot.integration_id == item.id,
                ApplicationSnapshot.collected_at >= datetime.now(UTC) - timedelta(days=7),
            )
            .order_by(ApplicationSnapshot.collected_at.desc())
            .limit(288)
        )
    )
    views = [SnapshotView.model_validate(row, from_attributes=True) for row in history]
    return ApplicationView(
        id=item.id,
        name=item.name,
        kind=item.kind,
        base_url=item.base_url,
        enabled=item.enabled,
        last_sync_at=item.last_sync_at,
        last_sync_status=item.last_sync_status,
        last_sync_error=item.last_sync_error,
        latest=views[0] if views else None,
        history=list(reversed(views)),
    )


@router.get("", response_model=list[ApplicationView])
async def list_applications(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[ApplicationView]:
    items = list(
        await database.scalars(select(ApplicationIntegration).order_by(ApplicationIntegration.name))
    )
    return [await application_view(database, item) for item in items]


@router.post("", response_model=ApplicationView, status_code=201)
async def create_application(
    payload: ApplicationInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> ApplicationView:
    item = ApplicationIntegration(
        name=payload.name.strip(),
        kind=payload.kind,
        base_url=safe_base_url(str(payload.base_url)),
        credential_encrypted=encrypt_secret(payload.api_key.strip()),
        created_by=auth[0].id,
    )
    database.add(item)
    await database.flush()
    await sync_application(database, item)
    return await application_view(database, item)


@router.post("/{integration_id}/sync", response_model=ApplicationView)
async def sync_now(
    integration_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> ApplicationView:
    item = await database.get(ApplicationIntegration, integration_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application integration not found")
    await sync_application(database, item)
    return await application_view(database, item)


@router.delete("/{integration_id}", status_code=204)
async def delete_application(
    integration_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    item = await database.get(ApplicationIntegration, integration_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application integration not found")
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="application.delete",
            target_type="application_integration",
            target_id=str(item.id),
        )
    )
    await database.delete(item)
    await database.commit()


async def application_sync_loop() -> None:
    while True:
        async with get_session_factory()() as database:
            items = list(
                await database.scalars(
                    select(ApplicationIntegration).where(ApplicationIntegration.enabled.is_(True))
                )
            )
            for item in items:
                await sync_application(database, item)
        await asyncio.sleep(300)
