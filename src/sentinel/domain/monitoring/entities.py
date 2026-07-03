from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.shared.entity import BaseEntity


@dataclass(kw_only=True)
class ConfigurationItem(BaseEntity):
    """Tracks a single configuration key inside a WordPress installation.

    ``config_source`` is the relative filename (``"wp-config.php"`` or
    ``".user.ini"``).  ``raw_value`` is the normalised string form of the
    current value (``None`` when the key is expected but absent from the
    file).  ``is_flagged`` is True when the setting violates a known
    security rule."""

    installation_id: UUID
    config_source: str
    key: str
    raw_value: str | None
    is_flagged: bool
    flag_reason: str | None
    is_present: bool = True
    last_seen_at: datetime

    def mark_seen(
        self,
        *,
        raw_value: str | None,
        is_flagged: bool,
        flag_reason: str | None,
        at: datetime,
    ) -> None:
        self.raw_value = raw_value
        self.is_flagged = is_flagged
        self.flag_reason = flag_reason
        self.is_present = True
        self.last_seen_at = at
        self.touch()

    def mark_absent(self, *, at: datetime) -> None:
        self.is_present = False
        self.last_seen_at = at
        self.touch()
