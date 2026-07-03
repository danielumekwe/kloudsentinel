from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme


class InstalledPluginResponse(BaseModel):
    id: UUID
    installation_id: UUID
    slug: str
    name: str
    version: str | None
    is_present: bool
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: InstalledPlugin) -> InstalledPluginResponse:
        return cls(
            id=entity.id,
            installation_id=entity.installation_id,
            slug=entity.slug,
            name=entity.name,
            version=entity.version,
            is_present=entity.is_present,
            last_seen_at=entity.last_seen_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class InstalledThemeResponse(BaseModel):
    id: UUID
    installation_id: UUID
    slug: str
    name: str
    version: str | None
    is_present: bool
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: InstalledTheme) -> InstalledThemeResponse:
        return cls(
            id=entity.id,
            installation_id=entity.installation_id,
            slug=entity.slug,
            name=entity.name,
            version=entity.version,
            is_present=entity.is_present,
            last_seen_at=entity.last_seen_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
