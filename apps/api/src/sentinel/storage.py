import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.auth import authenticated_session, csrf_protected_session
from sentinel.database import get_session
from sentinel.models import AuditEvent, Session, StorageFinding, StorageTarget, User

router = APIRouter(prefix="/api/v1/storage", tags=["storage analysis"])
SCAN_ROOT = Path("/scan")
MAX_FILES = 250_000


class TargetInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    relative_path: str = Field(default=".", max_length=500)
    large_file_mb: int = Field(default=1024, ge=1, le=1_000_000)
    old_file_days: int = Field(default=365, ge=1, le=3650)
    protected_paths: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("relative_path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("path must be relative to the read-only /scan mount")
        return str(path)


class FindingView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    relative_path: str
    item_type: str
    size_bytes: int
    modified_at: datetime
    reason: str
    protected: bool


class TargetView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    relative_path: str
    large_file_bytes: int
    old_file_days: int
    protected_paths: str
    last_scanned_at: datetime | None
    last_total_bytes: int
    last_file_count: int
    findings: list[FindingView] = Field(default_factory=list)


def resolve_target(relative: str) -> Path:
    root = SCAN_ROOT.resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "target escapes /scan")
    if not target.is_dir():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "mounted directory not found")
    return target


def collect_findings(root: Path, target: StorageTarget) -> tuple[list[StorageFinding], int, int]:
    protected = tuple(line for line in target.protected_paths.splitlines() if line)
    cutoff = datetime.now(UTC) - timedelta(days=target.old_file_days)
    findings: list[StorageFinding] = []
    total = count = 0
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
        for name in files:
            if count >= MAX_FILES:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    f"scan stopped at {MAX_FILES:,} files; choose a narrower target",
                )
            path = Path(directory) / name
            try:
                if path.is_symlink():
                    continue
                info = path.stat()
            except OSError:
                continue
            count += 1
            total += info.st_size
            relative = path.relative_to(root).as_posix()
            modified = datetime.fromtimestamp(info.st_mtime, UTC)
            reasons = []
            if info.st_size >= target.large_file_bytes:
                reasons.append("large file")
            if modified <= cutoff:
                reasons.append(f"not modified in {target.old_file_days}+ days")
            if reasons:
                findings.append(
                    StorageFinding(
                        target_id=target.id,
                        relative_path=relative,
                        size_bytes=info.st_size,
                        modified_at=modified,
                        reason="; ".join(reasons),
                        protected=any(
                            relative == item or relative.startswith(item + "/")
                            for item in protected
                        ),
                    )
                )
    return findings, total, count


@router.get("/targets", response_model=list[TargetView])
async def list_targets(
    database: Annotated[AsyncSession, Depends(get_session)],
    _auth: Annotated[tuple[User, Session], Depends(authenticated_session)],
) -> list[TargetView]:
    targets = list(await database.scalars(select(StorageTarget).order_by(StorageTarget.name)))
    result = []
    for target in targets:
        findings = list(
            await database.scalars(
                select(StorageFinding)
                .where(StorageFinding.target_id == target.id)
                .order_by(StorageFinding.size_bytes.desc())
                .limit(200)
            )
        )
        result.append(
            TargetView(
                **{
                    name: getattr(target, name)
                    for name in TargetView.model_fields
                    if name != "findings"
                },
                findings=findings,
            )
        )
    return result


@router.post("/targets", response_model=TargetView, status_code=201)
async def create_target(
    payload: TargetInput,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> TargetView:
    resolve_target(payload.relative_path)
    target = StorageTarget(
        name=payload.name.strip(),
        relative_path=payload.relative_path,
        large_file_bytes=payload.large_file_mb * 1_048_576,
        old_file_days=payload.old_file_days,
        protected_paths="\n".join(
            p.strip().replace("\\", "/").strip("/") for p in payload.protected_paths if p.strip()
        ),
    )
    database.add(target)
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="storage.target.create",
            target_type="storage_target",
            target_id=str(target.id),
        )
    )
    await database.commit()
    return TargetView(
        **{name: getattr(target, name) for name in TargetView.model_fields if name != "findings"},
        findings=[],
    )


@router.post("/targets/{target_id}/scan", response_model=TargetView)
async def scan_target(
    target_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> TargetView:
    target = await database.get(StorageTarget, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "storage target not found")
    root = resolve_target(target.relative_path)
    findings, total, count = await asyncio.to_thread(collect_findings, root, target)
    await database.execute(delete(StorageFinding).where(StorageFinding.target_id == target.id))
    database.add_all(findings)
    target.last_scanned_at = datetime.now(UTC)
    target.last_total_bytes = total
    target.last_file_count = count
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="storage.scan",
            target_type="storage_target",
            target_id=str(target.id),
        )
    )
    await database.commit()
    return TargetView(
        **{name: getattr(target, name) for name in TargetView.model_fields if name != "findings"},
        findings=sorted(findings, key=lambda item: item.size_bytes, reverse=True)[:200],
    )


@router.delete("/targets/{target_id}", status_code=204)
async def delete_target(
    target_id: uuid.UUID,
    database: Annotated[AsyncSession, Depends(get_session)],
    auth: Annotated[tuple[User, Session], Depends(csrf_protected_session)],
) -> None:
    target = await database.get(StorageTarget, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "storage target not found")
    await database.delete(target)
    database.add(
        AuditEvent(
            actor_user_id=auth[0].id,
            action="storage.target.delete",
            target_type="storage_target",
            target_id=str(target.id),
        )
    )
    await database.commit()
