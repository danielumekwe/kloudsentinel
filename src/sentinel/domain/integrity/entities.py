from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.integrity.value_objects import (
    ChangeType,
    RemediationActionType,
    RemediationOutcome,
    RemediationState,
)
from sentinel.domain.shared.entity import BaseEntity
from sentinel.domain.shared.exceptions import InvariantViolationError
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
    records of what was observed at ``detected_at`` — ``change_type`` and
    the hash fields never change after creation. ``severity`` is normally
    fixed too, with one controlled exception: ``escalate_severity`` lets a
    later, more context-aware analysis (e.g. "this is a WordPress core
    file") raise it, never lower it. What else can change is
    acknowledgement and remediation lifecycle state, tracked via
    ``remediation_state``.

    ``remediation_state`` starts at ``NONE`` and can move to ``QUARANTINED``
    (file moved out of place, reversibly), and from there to either
    ``RESTORED`` or ``DELETED`` (both terminal). A finding whose
    ``change_type`` is ``DELETED`` has no file left on disk to quarantine.
    """

    account_id: UUID
    relative_path: RelativeFilePath
    change_type: ChangeType
    severity: Severity
    previous_sha256: Sha256Hash | None
    current_sha256: Sha256Hash | None
    detected_at: datetime
    is_acknowledged: bool = False
    remediation_state: RemediationState = RemediationState.NONE
    quarantine_path: str | None = None
    quarantine_mode: str | None = None
    quarantine_size_bytes: int | None = None
    quarantine_owner_uid: int | None = None
    quarantine_owner_gid: int | None = None

    def acknowledge(self) -> None:
        self.is_acknowledged = True
        self.touch()

    def escalate_severity(self, to: Severity, *, at: datetime) -> None:
        """Raises ``severity``, never lowers it — a later pass with more
        context (e.g. "this is a named WordPress core file") can decide a
        finding was under-weighted at detection time, but should never be
        able to make a finding look less serious than it was first
        assessed to be."""
        if to.rank <= self.severity.rank:
            raise InvariantViolationError(
                f"Finding {self.id} severity {self.severity} cannot be escalated to {to}"
            )
        self.severity = to
        self.touch()

    def ensure_can_quarantine(self) -> None:
        if self.remediation_state is not RemediationState.NONE:
            raise InvariantViolationError(
                f"Finding {self.id} cannot be quarantined from state {self.remediation_state}"
            )
        if self.change_type is ChangeType.DELETED:
            raise InvariantViolationError(
                f"Finding {self.id} has no file on disk to quarantine (change_type=DELETED)"
            )

    def quarantine(
        self,
        *,
        quarantine_path: str,
        mode: str,
        size_bytes: int,
        owner_uid: int,
        owner_gid: int,
        at: datetime,
    ) -> None:
        self.ensure_can_quarantine()
        self.remediation_state = RemediationState.QUARANTINED
        self.quarantine_path = quarantine_path
        self.quarantine_mode = mode
        self.quarantine_size_bytes = size_bytes
        self.quarantine_owner_uid = owner_uid
        self.quarantine_owner_gid = owner_gid
        self.touch()

    def ensure_can_restore(self) -> None:
        if self.remediation_state is not RemediationState.QUARANTINED:
            raise InvariantViolationError(
                f"Finding {self.id} is not quarantined (state={self.remediation_state})"
            )

    def restore(self, *, at: datetime) -> None:
        self.ensure_can_restore()
        self.remediation_state = RemediationState.RESTORED
        self.quarantine_path = None
        self.quarantine_mode = None
        self.quarantine_size_bytes = None
        self.quarantine_owner_uid = None
        self.quarantine_owner_gid = None
        self.touch()

    def ensure_can_delete(self) -> None:
        if self.remediation_state is not RemediationState.QUARANTINED:
            raise InvariantViolationError(
                f"Finding {self.id} is not quarantined (state={self.remediation_state})"
            )

    def delete(self, *, at: datetime) -> None:
        self.ensure_can_delete()
        self.remediation_state = RemediationState.DELETED
        self.quarantine_path = None
        self.quarantine_mode = None
        self.quarantine_size_bytes = None
        self.quarantine_owner_uid = None
        self.quarantine_owner_gid = None
        self.touch()


@dataclass(kw_only=True)
class RemediationAction(BaseEntity):
    """Immutable audit-log record of one remediation attempt against an
    ``IntegrityFinding``. Unlike ``IntegrityFinding``, there are no mutators —
    a ``RemediationAction`` is constructed once, after the underlying
    filesystem operation has already succeeded or failed, with that outcome
    baked in."""

    finding_id: UUID
    account_id: UUID
    relative_path: RelativeFilePath
    action_type: RemediationActionType
    outcome: RemediationOutcome
    detail: str | None
    performed_at: datetime
