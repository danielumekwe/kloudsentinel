from __future__ import annotations

from uuid import uuid4

import pytest

from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding
from sentinel.domain.integrity.value_objects import ChangeType, RemediationState
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import InvariantViolationError
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash

_HASH_A = "a" * 64
_HASH_B = "b" * 64


def _baseline(*, is_active: bool = True) -> FileBaseline:
    return FileBaseline(
        account_id=uuid4(),
        relative_path=RelativeFilePath(value="public_html/index.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
        is_active=is_active,
    )


def _finding(*, change_type: ChangeType = ChangeType.MODIFIED) -> IntegrityFinding:
    return IntegrityFinding(
        account_id=uuid4(),
        relative_path=RelativeFilePath(value="public_html/index.php"),
        change_type=change_type,
        severity=Severity.HIGH,
        previous_sha256=Sha256Hash(value=_HASH_A),
        current_sha256=Sha256Hash(value=_HASH_B),
        detected_at=utcnow(),
    )


def test_baseline_update_replaces_fields_and_touches() -> None:
    baseline = _baseline()
    original_updated_at = baseline.updated_at
    new_seen_at = utcnow()

    baseline.update(sha256=Sha256Hash(value=_HASH_B), size_bytes=200, mode="600", at=new_seen_at)

    assert str(baseline.sha256) == _HASH_B
    assert baseline.size_bytes == 200
    assert baseline.mode == "600"
    assert baseline.last_verified_at == new_seen_at
    assert baseline.updated_at >= original_updated_at


def test_baseline_mark_removed_deactivates() -> None:
    baseline = _baseline(is_active=True)
    at = utcnow()

    baseline.mark_removed(at=at)

    assert baseline.is_active is False
    assert baseline.last_verified_at == at


def test_baseline_reactivate_restores_and_updates() -> None:
    baseline = _baseline(is_active=False)
    at = utcnow()

    baseline.reactivate(sha256=Sha256Hash(value=_HASH_B), size_bytes=50, mode="640", at=at)

    assert baseline.is_active is True
    assert str(baseline.sha256) == _HASH_B
    assert baseline.size_bytes == 50
    assert baseline.mode == "640"


def test_finding_acknowledge_sets_flag_and_touches() -> None:
    finding = _finding()
    original_updated_at = finding.updated_at

    finding.acknowledge()

    assert finding.is_acknowledged is True
    assert finding.updated_at >= original_updated_at


def test_finding_escalate_severity_raises_and_touches() -> None:
    finding = _finding()
    assert finding.severity is Severity.HIGH
    original_updated_at = finding.updated_at

    finding.escalate_severity(Severity.CRITICAL, at=utcnow())

    assert finding.severity is Severity.CRITICAL
    assert finding.updated_at >= original_updated_at


def test_finding_escalate_severity_rejects_same_severity() -> None:
    finding = _finding()

    with pytest.raises(InvariantViolationError):
        finding.escalate_severity(Severity.HIGH, at=utcnow())

    assert finding.severity is Severity.HIGH


def test_finding_escalate_severity_rejects_downgrade() -> None:
    finding = _finding()

    with pytest.raises(InvariantViolationError):
        finding.escalate_severity(Severity.MEDIUM, at=utcnow())

    assert finding.severity is Severity.HIGH


def test_finding_quarantine_sets_state_and_fields() -> None:
    finding = _finding()
    at = utcnow()

    finding.quarantine(
        quarantine_path="/var/lib/sentinel/quarantine/x/y",
        mode="644",
        size_bytes=10,
        owner_uid=1000,
        owner_gid=1000,
        at=at,
    )

    assert finding.remediation_state is RemediationState.QUARANTINED
    assert finding.quarantine_path == "/var/lib/sentinel/quarantine/x/y"
    assert finding.quarantine_mode == "644"
    assert finding.quarantine_size_bytes == 10
    assert finding.quarantine_owner_uid == 1000
    assert finding.quarantine_owner_gid == 1000


def test_finding_quarantine_rejects_deleted_change_type() -> None:
    finding = _finding(change_type=ChangeType.DELETED)

    with pytest.raises(InvariantViolationError):
        finding.ensure_can_quarantine()


def test_finding_quarantine_rejects_already_quarantined() -> None:
    finding = _finding()
    finding.quarantine(
        quarantine_path="/q/path",
        mode="644",
        size_bytes=10,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )

    with pytest.raises(InvariantViolationError):
        finding.quarantine(
            quarantine_path="/q/path2",
            mode="644",
            size_bytes=10,
            owner_uid=1000,
            owner_gid=1000,
            at=utcnow(),
        )


def test_finding_restore_clears_quarantine_fields() -> None:
    finding = _finding()
    finding.quarantine(
        quarantine_path="/q/path",
        mode="644",
        size_bytes=10,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )

    finding.restore(at=utcnow())

    assert finding.remediation_state is RemediationState.RESTORED
    assert finding.quarantine_path is None
    assert finding.quarantine_mode is None
    assert finding.quarantine_size_bytes is None
    assert finding.quarantine_owner_uid is None
    assert finding.quarantine_owner_gid is None


def test_finding_restore_requires_quarantined_state() -> None:
    finding = _finding()

    with pytest.raises(InvariantViolationError):
        finding.restore(at=utcnow())


def test_finding_delete_clears_quarantine_fields() -> None:
    finding = _finding()
    finding.quarantine(
        quarantine_path="/q/path",
        mode="644",
        size_bytes=10,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )

    finding.delete(at=utcnow())

    assert finding.remediation_state is RemediationState.DELETED
    assert finding.quarantine_path is None
    assert finding.quarantine_owner_uid is None
    assert finding.quarantine_owner_gid is None


def test_finding_delete_requires_quarantined_state() -> None:
    finding = _finding()

    with pytest.raises(InvariantViolationError):
        finding.delete(at=utcnow())


def test_finding_delete_rejects_after_restore() -> None:
    finding = _finding()
    finding.quarantine(
        quarantine_path="/q/path",
        mode="644",
        size_bytes=10,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )
    finding.restore(at=utcnow())

    with pytest.raises(InvariantViolationError):
        finding.delete(at=utcnow())
