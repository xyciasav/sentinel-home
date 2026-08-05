import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Response, status
from fastapi.responses import RedirectResponse

from sentinel.config import get_settings
from sentinel.health import database_status, redis_status
from sentinel.setup import router as setup_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_settings()
    yield


app = FastAPI(title="Sentinel Home API", version=get_settings().sentinel_version, lifespan=lifespan)
app.include_router(setup_router)


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.get("/api/v1/health/live", tags=["health"])
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/health/ready", tags=["health"])
async def readiness(response: Response) -> dict[str, Any]:
    settings = get_settings()
    database, redis = await asyncio.gather(database_status(settings), redis_status(settings))
    dependencies = {"database": database.__dict__, "redis": redis.__dict__}
    ready = all(item.status in {"ok", "disabled"} for item in (database, redis))
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if ready else "degraded", "dependencies": dependencies}


@app.get("/api/v1/version", tags=["system"])
async def version() -> dict[str, str]:
    settings = get_settings()
    return {"version": settings.sentinel_version, "environment": settings.sentinel_environment}
