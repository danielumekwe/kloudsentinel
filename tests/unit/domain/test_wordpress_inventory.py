from __future__ import annotations

from uuid import uuid4

from sentinel.domain.shared.entity import utcnow
from sentinel.domain.wordpress.inventory.entities import WordPressCronJob


def _cron_job() -> WordPressCronJob:
    return WordPressCronJob(
        installation_id=uuid4(),
        command="/usr/bin/php /home/bob/public_html/wp-cron.php",
        schedule_raw="*/15 * * * *",
        last_seen_at=utcnow(),
    )


def test_new_cron_job_defaults_to_present_and_not_suspicious() -> None:
    job = _cron_job()

    assert job.is_present is True
    assert job.is_suspicious is False
    assert job.flag_reason is None


def test_mark_seen_updates_fields_and_touches() -> None:
    job = _cron_job()
    original_updated_at = job.updated_at
    at = utcnow()

    job.mark_seen(
        schedule_raw="0 * * * *",
        is_suspicious=True,
        flag_reason="command contains suspicious pattern: 'curl '",
        at=at,
    )

    assert job.schedule_raw == "0 * * * *"
    assert job.is_suspicious is True
    assert job.flag_reason == "command contains suspicious pattern: 'curl '"
    assert job.is_present is True
    assert job.last_seen_at == at
    assert job.updated_at >= original_updated_at


def test_mark_absent_clears_presence() -> None:
    job = _cron_job()
    at = utcnow()

    job.mark_absent(at=at)

    assert job.is_present is False
    assert job.last_seen_at == at
