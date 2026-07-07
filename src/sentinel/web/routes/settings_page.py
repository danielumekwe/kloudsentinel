from __future__ import annotations

from fastapi import APIRouter, Request, Response

from sentinel.api.dependencies import AppSettings
from sentinel.web.dependencies import RequireAdminSession, templates

router = APIRouter(prefix="/settings", tags=["dashboard-settings"])


@router.get("")
async def settings_page(
    request: Request,
    settings: AppSettings,
    admin_user: RequireAdminSession,
) -> Response:
    """Read-only for v1 — shows the running configuration and how to change
    it (env file + restart), rather than exposing runtime-mutable settings.
    See docs/deployment/ for the full deployment/config reference."""
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "admin_user": admin_user,
            "settings": settings,
            "csrf_token": request.state.admin_session.csrf_token,
        },
    )
