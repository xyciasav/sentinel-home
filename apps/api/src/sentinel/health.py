import asyncio
from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel.config import Settings


@dataclass(frozen=True)
class DependencyStatus:
    status: str
    detail: str | None = None


async def database_status(settings: Settings) -> DependencyStatus:
    if not settings.database_url:
        return DependencyStatus("disabled")
    url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(url, pool_pre_ping=True)
    try:
        async with asyncio.timeout(2):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        return DependencyStatus("ok")
    except Exception as exc:
        return DependencyStatus("unavailable", type(exc).__name__)
    finally:
        await engine.dispose()


async def redis_status(settings: Settings) -> DependencyStatus:
    if not settings.redis_url:
        return DependencyStatus("disabled")
    client = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
    try:
        async with asyncio.timeout(2):
            await client.ping()
        return DependencyStatus("ok")
    except Exception as exc:
        return DependencyStatus("unavailable", type(exc).__name__)
    finally:
        await client.aclose()
