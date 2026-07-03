from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.infrastructure.persistence.database import Base
from sentinel.infrastructure.persistence.types import GUID


class ConfigurationItemModel(Base):
    __tablename__ = "configuration_items"
    __table_args__ = (UniqueConstraint("installation_id", "config_source", "key"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    installation_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("wp_installations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    config_source: Mapped[str] = mapped_column(String(128), nullable=False)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    flag_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
