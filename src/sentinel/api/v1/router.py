from __future__ import annotations

from fastapi import APIRouter

from sentinel.api.v1 import (
    accounts,
    health,
    installations,
    integrity,
    intelligence,
    inventory,
    monitoring,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(accounts.router)
api_router.include_router(installations.router)
api_router.include_router(integrity.router)
api_router.include_router(inventory.router)
api_router.include_router(monitoring.router)
api_router.include_router(intelligence.router)
