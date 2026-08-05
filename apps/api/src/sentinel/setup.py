from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.database import get_session
from sentinel.models import User

router = APIRouter(prefix="/api/v1/setup", tags=["setup"])


class SetupStatus(BaseModel):
    initialized: bool
    administrator_count: int


@router.get("/status", response_model=SetupStatus)
async def setup_status(session: Annotated[AsyncSession, Depends(get_session)]) -> SetupStatus:
    count = await session.scalar(
        select(func.count()).select_from(User).where(User.is_admin.is_(True))
    )
    administrator_count = count or 0
    return SetupStatus(initialized=administrator_count > 0, administrator_count=administrator_count)
