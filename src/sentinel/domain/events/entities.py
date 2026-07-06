from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.shared.entity import BaseEntity
from sentinel.domain.shared.value_objects import Severity


@dataclass(kw_only=True)
class SecurityEvent(BaseEntity):
    """One normalized fact observed by any bounded context — a raised
    ``IntegrityFinding``, a malicious temp-file observation, a future
    log_collection alert, and so on.

    This is the durable, cross-process hand-off point between detection and
    correlation: Sentinel runs as two separate OS processes (the API and the
    scheduler worker) that share nothing but the database, so "publish" here
    means "persist a row" and "subscribe" means a scheduled job querying rows
    where ``processed_at IS NULL`` — event-driven architecture implemented
    with the same poll-based, DB-mediated pattern every other job already
    uses, rather than an in-memory bus that would only ever see events
    raised in whichever process created them.
    """

    event_type: str
    source_context: str
    account_id: UUID | None
    severity: Severity
    payload: dict[str, object]
    occurred_at: datetime
    processed_at: datetime | None = None

    def mark_processed(self, *, at: datetime) -> None:
        self.processed_at = at
        self.touch()
