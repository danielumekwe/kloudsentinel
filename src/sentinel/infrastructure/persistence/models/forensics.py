from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.infrastructure.persistence.database import Base
from sentinel.infrastructure.persistence.types import GUID


class TempFileObservationModel(Base):
    __tablename__ = "temp_file_observations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    absolute_path: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    verdict_reason: Mapped[str] = mapped_column(String(512), nullable=False)
    matched_rule_ids: Mapped[str] = mapped_column(Text, nullable=False)
    process_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    account_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("cpanel_accounts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    file_permissions: Mapped[str | None] = mapped_column(String(8), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    server_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("servers.id", ondelete="CASCADE"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
