from __future__ import annotations

from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.observability.value_objects import JobHeartbeatStatus
from sentinel.domain.shared.entity import utcnow


def _heartbeat() -> JobHeartbeat:
    return JobHeartbeat(
        job_id="discovery",
        status=JobHeartbeatStatus.SUCCESS,
        last_run_at=utcnow(),
        last_duration_ms=12.5,
    )


def test_new_heartbeat_has_no_error() -> None:
    heartbeat = _heartbeat()

    assert heartbeat.last_error is None


def test_record_updates_fields_and_touches() -> None:
    heartbeat = _heartbeat()
    original_updated_at = heartbeat.updated_at
    at = utcnow()

    heartbeat.record(status=JobHeartbeatStatus.FAILURE, at=at, duration_ms=99.0, error="boom")

    assert heartbeat.status is JobHeartbeatStatus.FAILURE
    assert heartbeat.last_run_at == at
    assert heartbeat.last_duration_ms == 99.0
    assert heartbeat.last_error == "boom"
    assert heartbeat.updated_at >= original_updated_at


def test_record_clears_previous_error_on_success() -> None:
    heartbeat = _heartbeat()
    heartbeat.record(status=JobHeartbeatStatus.FAILURE, at=utcnow(), duration_ms=1.0, error="boom")

    heartbeat.record(status=JobHeartbeatStatus.SUCCESS, at=utcnow(), duration_ms=2.0, error=None)

    assert heartbeat.status is JobHeartbeatStatus.SUCCESS
    assert heartbeat.last_error is None
