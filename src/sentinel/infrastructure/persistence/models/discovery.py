from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.infrastructure.persistence.database import Base
from sentinel.infrastructure.persistence.types import GUID


class ServerModel(Base):
    __tablename__ = "servers"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    os_info: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class CpanelAccountModel(Base):
    __tablename__ = "cpanel_accounts"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    server_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    username: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    primary_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    home_directory: Mapped[str] = mapped_column(String(1024), nullable=False)
    is_suspended: Mapped[bool] = mapped_column(Boolean, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class WordPressInstallationModel(Base):
    __tablename__ = "wp_installations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    cpanel_account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cpanel_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    absolute_path: Mapped[str] = mapped_column(
        String(1024), nullable=False, unique=True, index=True
    )
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    wp_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_multisite: Mapped[bool] = mapped_column(Boolean, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    php_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
