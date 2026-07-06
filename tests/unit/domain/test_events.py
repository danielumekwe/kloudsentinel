from __future__ import annotations

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import Severity


def _event() -> SecurityEvent:
    return SecurityEvent(
        event_type="temp_file_malicious",
        source_context="forensics",
        account_id=None,
        severity=Severity.CRITICAL,
        payload={"absolute_path": "/tmp/update_abc.php"},
        occurred_at=utcnow(),
    )


def test_new_event_is_unprocessed() -> None:
    event = _event()

    assert event.processed_at is None


def test_mark_processed_sets_timestamp_and_touches() -> None:
    event = _event()
    original_updated_at = event.updated_at
    at = utcnow()

    event.mark_processed(at=at)

    assert event.processed_at == at
    assert event.updated_at >= original_updated_at
