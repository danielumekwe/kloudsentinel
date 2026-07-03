from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.shared.entity import BaseEntity


@dataclass(kw_only=True)
class InstalledPlugin(BaseEntity):
    installation_id: UUID
    slug: str
    name: str
    version: str | None
    is_present: bool = True
    last_seen_at: datetime

    def mark_seen(self, *, name: str, version: str | None, at: datetime) -> None:
        self.name = name
        self.version = version
        self.is_present = True
        self.last_seen_at = at
        self.touch()

    def mark_absent(self, *, at: datetime) -> None:
        self.is_present = False
        self.last_seen_at = at
        self.touch()


@dataclass(kw_only=True)
class InstalledTheme(BaseEntity):
    installation_id: UUID
    slug: str
    name: str
    version: str | None
    is_present: bool = True
    last_seen_at: datetime

    def mark_seen(self, *, name: str, version: str | None, at: datetime) -> None:
        self.name = name
        self.version = version
        self.is_present = True
        self.last_seen_at = at
        self.touch()

    def mark_absent(self, *, at: datetime) -> None:
        self.is_present = False
        self.last_seen_at = at
        self.touch()
