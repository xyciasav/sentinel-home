from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.config import get_settings


def async_database_url(url: str) -> str:
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


@lru_cache
def get_engine() -> AsyncEngine:
    database_url = get_settings().database_url
    if not database_url:
        raise RuntimeError("DATABASE_URL is required for database operations")
    return create_async_engine(async_database_url(database_url), pool_pre_ping=True)


@lru_cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_session_factory()() as session:
        yield session
