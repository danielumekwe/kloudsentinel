from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.infrastructure.persistence.database import Base
from sentinel.infrastructure.persistence.types import GUID


class AdminUserModel(Base):
    """A dashboard login — distinct from `ApiKeyModel`, which authenticates
    machine callers of `/api/v1/*`. Password is never stored in plaintext,
    only bcrypt's own hash (which already embeds its salt)."""

    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AdminSessionModel(Base):
    """A logged-in dashboard session. Same "store only a hash" shape as
    `ApiKeyModel.key_hash` — the cookie holds the raw opaque token, only
    its SHA-256 hash is persisted, so a database read alone can never
    reveal a value that would let someone log in. `csrf_token` is a
    separate, non-secret nonce embedded in every form the session renders,
    checked on state-changing POSTs to prevent cross-site request forgery
    (the API's `RequireApiKey` needs no such defense — bearer tokens
    aren't sent automatically by a browser the way cookies are)."""

    __tablename__ = "admin_sessions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    admin_user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("admin_users.id"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
