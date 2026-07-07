from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Annotated

from fastapi import Depends, Form, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.api.dependencies import DbSession
from sentinel.config import Settings
from sentinel.domain.shared.entity import ensure_utc, utcnow
from sentinel.infrastructure.persistence.models import AdminSessionModel, AdminUserModel

SESSION_COOKIE_NAME = "sentinel_session"

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class RedirectToLogin(Exception):  # noqa: N818
    """Raised instead of a bare 401 when a browser request has no valid
    admin session — this is a page load, not an API client, so the right
    response is a redirect to the login form. Caught by an exception
    handler registered in `bootstrap.py` (mirrors how `RequireApiKey`
    raises `HTTPException` directly, since that path *is* an API client)."""


async def require_admin_session(request: Request, session: DbSession) -> AdminUserModel:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token is not None:
        result = await session.execute(
            select(AdminSessionModel).where(AdminSessionModel.token_hash == hash_token(raw_token))
        )
        admin_session = result.scalar_one_or_none()
        if (
            admin_session is not None
            and admin_session.revoked_at is None
            and ensure_utc(admin_session.expires_at) > utcnow()
        ):
            admin_user = await session.get(AdminUserModel, admin_session.admin_user_id)
            if admin_user is not None and admin_user.is_active:
                admin_session.last_used_at = utcnow()
                request.state.admin_session = admin_session
                return admin_user

    raise RedirectToLogin()


RequireAdminSession = Annotated[AdminUserModel, Depends(require_admin_session)]


def require_csrf_token(
    request: Request,
    admin_user: RequireAdminSession,
    csrf_token: Annotated[str, Form()],
) -> None:
    """Every state-changing dashboard POST needs this — unlike the JSON
    API's bearer-token `RequireApiKey`, a browser sends the session cookie
    automatically on any cross-site form submission, so cookie auth alone
    doesn't prove the request came from Sentinel's own page."""
    del admin_user
    admin_session: AdminSessionModel = request.state.admin_session
    if not secrets.compare_digest(csrf_token, admin_session.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


RequireCsrfToken = Annotated[None, Depends(require_csrf_token)]


def create_session_cookie_value(
    session: AsyncSession, *, admin_user: AdminUserModel, settings: Settings
) -> tuple[str, timedelta]:
    """Not itself a request dependency — a small helper shared by the login
    route to keep session-creation logic in one place."""
    raw_token = secrets.token_urlsafe(32)
    ttl = timedelta(hours=settings.admin_session_ttl_hours)
    session.add(
        AdminSessionModel(
            admin_user_id=admin_user.id,
            token_hash=hash_token(raw_token),
            csrf_token=secrets.token_urlsafe(24),
            created_at=utcnow(),
            expires_at=utcnow() + ttl,
        )
    )
    return raw_token, ttl
