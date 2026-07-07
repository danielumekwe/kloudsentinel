from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinel.domain.discovery.entities import CpanelAccount, WordPressInstallation


class CpanelAccountResponse(BaseModel):
    id: UUID
    server_id: UUID
    username: str
    primary_domain: str
    home_directory: str
    is_suspended: bool
    is_active: bool
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: CpanelAccount) -> CpanelAccountResponse:
        return cls(
            id=entity.id,
            server_id=entity.server_id,
            username=str(entity.username),
            primary_domain=str(entity.primary_domain),
            home_directory=str(entity.home_directory),
            is_suspended=entity.is_suspended,
            is_active=entity.is_active,
            last_seen_at=entity.last_seen_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class WordPressInstallationResponse(BaseModel):
    id: UUID
    cpanel_account_id: UUID
    absolute_path: str
    domain: str | None
    wp_version: str | None
    php_version: str | None
    is_multisite: bool
    is_active: bool
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: WordPressInstallation) -> WordPressInstallationResponse:
        return cls(
            id=entity.id,
            cpanel_account_id=entity.cpanel_account_id,
            absolute_path=str(entity.absolute_path),
            domain=str(entity.domain) if entity.domain is not None else None,
            wp_version=entity.wp_version,
            php_version=entity.php_version,
            is_multisite=entity.is_multisite,
            is_active=entity.is_active,
            last_seen_at=entity.last_seen_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
