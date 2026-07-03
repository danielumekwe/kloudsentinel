from __future__ import annotations

import time

from fastapi import APIRouter
from sqlalchemy import text

from sentinel.api.dependencies import DbSession
from sentinel.api.schemas.health import HealthStatus, ReadinessCheck, ReadinessStatus

router = APIRouter(prefix="/health", tags=["health"])

_START_TIME = time.monotonic()


@router.get("", response_model=HealthStatus)
async def liveness() -> HealthStatus:
    return HealthStatus(status="ok", uptime_seconds=round(time.monotonic() - _START_TIME, 1))


@router.get("/ready", response_model=ReadinessStatus)
async def readiness(session: DbSession) -> ReadinessStatus:
    try:
        await session.execute(text("SELECT 1"))
        database_check = "ok"
    except Exception:
        database_check = "error"

    overall = "ready" if database_check == "ok" else "not_ready"
    return ReadinessStatus(status=overall, checks=ReadinessCheck(database=database_check))
