from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.infrastructure.persistence.database import Base
from sentinel.infrastructure.persistence.types import GUID


class FileBaselineModel(Base):
    __tablename__ = "file_baselines"
    __table_args__ = (UniqueConstraint("account_id", "relative_path"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cpanel_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mode: Mapped[str] = mapped_column(String(4), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_verified_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class IntegrityFindingModel(Base):
    __tablename__ = "integrity_findings"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cpanel_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
