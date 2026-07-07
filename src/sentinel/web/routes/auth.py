from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from sentinel.api.dependencies import AppSettings, DbSession
from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.models import AdminUserModel
from sentinel.infrastructure.security.passwords import DUMMY_PASSWORD_HASH, verify_password
from sentinel.web.dependencies import (
    SESSION_COOKIE_NAME,
    RequireAdminSession,
    RequireCsrfToken,
    create_session_cookie_value,
    templates,
)

router = APIRouter(tags=["dashboard-auth"])


@router.get("/login")
async def login_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    session: DbSession,
    settings: AppSettings,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> Response:
    result = await session.execute(
        select(AdminUserModel).where(AdminUserModel.username == username)
    )
    admin_user = result.scalar_one_or_none()

    # Always run a real bcrypt comparison, even against a dummy hash when no
    # such user exists — otherwise a nonexistent username short-circuits
    # before verify_password() runs and returns near-instantly, while a real
    # username takes bcrypt's ~100ms+, letting an attacker enumerate valid
    # usernames purely from response timing.
    password_hash = admin_user.password_hash if admin_user is not None else DUMMY_PASSWORD_HASH
    password_ok = verify_password(password, password_hash)

    if admin_user is None or not admin_user.is_active or not password_ok:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    admin_user.last_login_at = utcnow()
    raw_token, ttl = create_session_cookie_value(session, admin_user=admin_user, settings=settings)

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        httponly=True,
        samesite="lax",
        secure=settings.environment == "production",
        max_age=int(ttl.total_seconds()),
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    admin_user: RequireAdminSession,
    _csrf: RequireCsrfToken,
) -> RedirectResponse:
    del admin_user
    request.state.admin_session.revoked_at = utcnow()

    response = RedirectResponse(url="/dashboard/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response
