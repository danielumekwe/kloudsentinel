from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import BaseEntity
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName


@dataclass(kw_only=True)
class Server(BaseEntity):
    """The host this agent runs on. In practice a singleton row: one running
    agent instance reports exactly one ``Server`` record, which anchors every
    ``CpanelAccount`` discovered on it."""

    hostname: str
    os_info: str
    agent_version: str
    last_seen_at: datetime

    def mark_seen(self, *, at: datetime) -> None:
        self.last_seen_at = at
        self.touch()


@dataclass(kw_only=True)
class CpanelAccount(BaseEntity):
    server_id: UUID
    username: LinuxUsername
    primary_domain: DomainName
    home_directory: AbsoluteFilePath
    is_suspended: bool
    last_seen_at: datetime
    is_active: bool = True

    def mark_seen(self, *, primary_domain: DomainName, is_suspended: bool, at: datetime) -> None:
        self.primary_domain = primary_domain
        self.is_suspended = is_suspended
        self.last_seen_at = at
        self.is_active = True
        self.touch()

    def mark_inactive(self) -> None:
        self.is_active = False
        self.touch()


@dataclass(kw_only=True)
class WordPressInstallation(BaseEntity):
    cpanel_account_id: UUID
    absolute_path: AbsoluteFilePath
    domain: DomainName | None
    wp_version: str | None
    is_multisite: bool
    last_seen_at: datetime
    is_active: bool = True

    def mark_seen(
        self,
        *,
        domain: DomainName | None,
        wp_version: str | None,
        is_multisite: bool,
        at: datetime,
    ) -> None:
        self.domain = domain
        self.wp_version = wp_version
        self.is_multisite = is_multisite
        self.last_seen_at = at
        self.is_active = True
        self.touch()

    def mark_inactive(self) -> None:
        self.is_active = False
        self.touch()
