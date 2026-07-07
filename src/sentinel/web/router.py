from __future__ import annotations

from fastapi import APIRouter

from sentinel.web.routes import auth, dashboard, quarantine, scans, settings_page, threats

web_router = APIRouter(prefix="/dashboard")
web_router.include_router(auth.router)
web_router.include_router(dashboard.router)
web_router.include_router(threats.router)
web_router.include_router(quarantine.router)
web_router.include_router(scans.router)
web_router.include_router(settings_page.router)
