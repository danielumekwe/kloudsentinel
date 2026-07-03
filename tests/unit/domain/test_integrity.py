from __future__ import annotations

from uuid import uuid4

from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding
from sentinel.domain.integrity.value_objects import ChangeType
from sentinel.domain.shared.entity import utcnow
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
    finding = IntegrityFinding(
        account_id=uuid4(),
        relative_path=RelativeFilePath(value="public_html/index.php"),
        change_type=ChangeType.MODIFIED,
        severity=Severity.HIGH,
        previous_sha256=Sha256Hash(value=_HASH_A),
        current_sha256=Sha256Hash(value=_HASH_B),
        detected_at=utcnow(),
    )
    original_updated_at = finding.updated_at

    finding.acknowledge()

    assert finding.is_acknowledged is True
    assert finding.updated_at >= original_updated_at
