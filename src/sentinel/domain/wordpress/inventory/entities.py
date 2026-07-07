from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.shared.entity import BaseEntity


@dataclass(kw_only=True)
class WordPressCronJob(BaseEntity):
    """One system-crontab entry belonging to the account that owns a
    WordPress installation.

    Deliberately scoped to what's visible on disk: real `wp_options`-based
    WP-Cron entries live inside the site's own MySQL database, and Sentinel
    has no database-client capability anywhere in its architecture — adding
    one is a materially larger, separate piece of work than anything else
    here. System crontab entries are the persistence vector this actually
    catches (a webshell re-dropping itself via `* * * * * curl ... | sh`).
    """

    installation_id: UUID
    command: str
    schedule_raw: str
    is_suspicious: bool = False
    flag_reason: str | None = None
    is_present: bool = True
    last_seen_at: datetime

    def mark_seen(
        self,
        *,
        schedule_raw: str,
        is_suspicious: bool,
        flag_reason: str | None,
        at: datetime,
    ) -> None:
        self.schedule_raw = schedule_raw
        self.is_suspicious = is_suspicious
        self.flag_reason = flag_reason
        self.is_present = True
        self.last_seen_at = at
        self.touch()

    def mark_absent(self, *, at: datetime) -> None:
        self.is_present = False
        self.last_seen_at = at
        self.touch()
