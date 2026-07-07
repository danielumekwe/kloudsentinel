from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.infrastructure.persistence.database import Base
from sentinel.infrastructure.persistence.types import GUID


class WordPressCronJobModel(Base):
    __tablename__ = "wordpress_cron_jobs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    installation_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("wp_installations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    command: Mapped[str] = mapped_column(Text, nullable=False)
    schedule_raw: Mapped[str] = mapped_column(String(128), nullable=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    flag_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
