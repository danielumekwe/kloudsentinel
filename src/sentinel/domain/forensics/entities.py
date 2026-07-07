from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.forensics.value_objects import ProcessContext, TempFileVerdict
from sentinel.domain.shared.entity import BaseEntity
from sentinel.domain.shared.value_objects import AbsoluteFilePath, Sha256Hash


@dataclass(kw_only=True)
class TempFileObservation(BaseEntity):
    """One script-like file (``.php``/``.pl``/``.cgi``/``.sh``) observed under
    a watched temp directory (``/tmp``, ``/var/tmp``, ``/dev/shm``) — the
    building block the Incident Correlation Engine groups to recognize e.g.
    six unrelated-looking ``/tmp/update_*.php`` alerts as one attack.

    Immutable once created: a temp file is a point-in-time fact, not
    something Sentinel expects to see change in place.
    """

    absolute_path: AbsoluteFilePath
    sha256: Sha256Hash | None
    owner: str
    size_bytes: int
    verdict: TempFileVerdict
    verdict_reason: str
    matched_rule_ids: tuple[str, ...]
    process: ProcessContext | None
    account_id: UUID | None
    detected_at: datetime
    file_permissions: str | None = None
    mime_type: str | None = None
    server_id: UUID | None = None
