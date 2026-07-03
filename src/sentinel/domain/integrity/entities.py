from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.integrity.value_objects import ChangeType
from sentinel.domain.shared.entity import BaseEntity
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash


@dataclass(kw_only=True)
class FileBaseline(BaseEntity):
    """The known-good state of one file under a cPanel account's home
    directory, as of the last scan that saw it. ``is_active=False`` means the
    file was present at some point but is no longer found on disk — kept
    rather than deleted so its history isn't lost, same convention as
    ``CpanelAccount.is_active``."""

    account_id: UUID
    relative_path: RelativeFilePath
    sha256: Sha256Hash
    size_bytes: int
    mode: str
    last_verified_at: datetime
    is_active: bool = True

    def update(self, *, sha256: Sha256Hash, size_bytes: int, mode: str, at: datetime) -> None:
        self.sha256 = sha256
        self.size_bytes = size_bytes
        self.mode = mode
        self.last_verified_at = at
        self.touch()

    def reactivate(self, *, sha256: Sha256Hash, size_bytes: int, mode: str, at: datetime) -> None:
        """A file that was previously marked removed has reappeared. Revives
        the existing baseline row rather than creating a new one, since
        ``(account_id, relative_path)`` is unique — a deleted-then-recreated
        file must reuse its original baseline identity."""
        self.is_active = True
        self.update(sha256=sha256, size_bytes=size_bytes, mode=mode, at=at)

    def mark_removed(self, *, at: datetime) -> None:
        self.is_active = False
        self.last_verified_at = at
        self.touch()


@dataclass(kw_only=True)
class IntegrityFinding(BaseEntity):
    """One detected file-integrity change. Findings are immutable historical
    records of what was observed at ``detected_at`` — the only mutation
    allowed afterwards is acknowledging them, never editing the finding
    itself."""

    account_id: UUID
    relative_path: RelativeFilePath
    change_type: ChangeType
    severity: Severity
    previous_sha256: Sha256Hash | None
    current_sha256: Sha256Hash | None
    detected_at: datetime
    is_acknowledged: bool = False

    def acknowledge(self) -> None:
        self.is_acknowledged = True
        self.touch()
