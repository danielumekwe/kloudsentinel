from __future__ import annotations

from pydantic import BaseModel


class HealthStatus(BaseModel):
    status: str
    uptime_seconds: float


class ReadinessCheck(BaseModel):
    database: str


class ReadinessStatus(BaseModel):
    status: str
    checks: ReadinessCheck
