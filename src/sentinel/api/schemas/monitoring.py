from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinel.domain.monitoring.entities import ConfigurationItem


class ConfigurationItemResponse(BaseModel):
    id: UUID
    installation_id: UUID
    config_source: str
    key: str
    raw_value: str | None
    is_flagged: bool
    flag_reason: str | None
    is_present: bool
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: ConfigurationItem) -> ConfigurationItemResponse:
        return cls(
            id=entity.id,
            installation_id=entity.installation_id,
            config_source=entity.config_source,
            key=entity.key,
            raw_value=entity.raw_value,
            is_flagged=entity.is_flagged,
            flag_reason=entity.flag_reason,
            is_present=entity.is_present,
            last_seen_at=entity.last_seen_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
