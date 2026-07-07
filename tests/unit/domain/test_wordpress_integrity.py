from __future__ import annotations

from sentinel.domain.shared.entity import utcnow
from sentinel.domain.wordpress.integrity.entities import CoreChecksumRecord


def test_core_checksum_record_holds_fields_verbatim() -> None:
    at = utcnow()

    record = CoreChecksumRecord(
        wp_version="6.5.2",
        relative_path="wp-includes/version.php",
        sha256="a" * 64,
        fetched_at=at,
    )

    assert record.wp_version == "6.5.2"
    assert record.relative_path == "wp-includes/version.php"
    assert record.sha256 == "a" * 64
    assert record.fetched_at == at
