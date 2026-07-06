from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.domain.shared.entity import BaseEntity, ensure_utc
from sentinel.domain.shared.exceptions import ValidationError
from sentinel.domain.shared.value_objects import (
    AbsoluteFilePath,
    DomainName,
    RelativeFilePath,
    Severity,
    Sha256Hash,
)

VALID_HASH = "a" * 64


def test_entity_equality_is_identity_based() -> None:
    first = BaseEntity()
    second = BaseEntity(id=first.id)
    third = BaseEntity()

    assert first == second
    assert first != third
    assert hash(first) == hash(second)


def test_entity_touch_updates_timestamp() -> None:
    entity = BaseEntity()
    original = entity.updated_at
    entity.touch()
    assert entity.updated_at >= original


def test_ensure_utc_attaches_tzinfo_to_naive_datetime() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)

    result = ensure_utc(naive)

    assert result.tzinfo is UTC
    assert result.replace(tzinfo=None) == naive


def test_ensure_utc_leaves_aware_datetime_unchanged() -> None:
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    result = ensure_utc(aware)

    assert result is aware


def test_sha256_hash_normalizes_case() -> None:
    upper = Sha256Hash(value=VALID_HASH.upper())
    lower = Sha256Hash(value=VALID_HASH)
    assert upper == lower
    assert str(upper) == VALID_HASH


@pytest.mark.parametrize("bad_value", ["", "not-a-hash", "a" * 63, "g" * 64])
def test_sha256_hash_rejects_invalid_values(bad_value: str) -> None:
    with pytest.raises(ValidationError):
        Sha256Hash(value=bad_value)


def test_relative_file_path_accepts_valid_path() -> None:
    path = RelativeFilePath(value="wp-content/plugins/akismet/akismet.php")
    assert str(path) == "wp-content/plugins/akismet/akismet.php"


@pytest.mark.parametrize(
    "bad_value",
    ["", "/etc/passwd", "../../etc/passwd", "wp-content/../../../etc/passwd"],
)
def test_relative_file_path_rejects_unsafe_values(bad_value: str) -> None:
    with pytest.raises(ValidationError):
        RelativeFilePath(value=bad_value)


def test_severity_rank_orders_critical_above_info() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_domain_name_normalizes_case_and_trailing_dot() -> None:
    assert str(DomainName(value="Example.COM.")) == "example.com"


@pytest.mark.parametrize(
    "bad_value", ["", "not a domain", "-example.com", "example.com-", "example", "a..com"]
)
def test_domain_name_rejects_invalid_values(bad_value: str) -> None:
    with pytest.raises(ValidationError):
        DomainName(value=bad_value)


def test_absolute_file_path_accepts_valid_path() -> None:
    path = AbsoluteFilePath(value="/home/exampleuser/public_html")
    assert str(path) == "/home/exampleuser/public_html"


@pytest.mark.parametrize(
    "bad_value", ["", "relative/path", "/home/user/../../etc/passwd", "/home/../etc"]
)
def test_absolute_file_path_rejects_unsafe_values(bad_value: str) -> None:
    with pytest.raises(ValidationError):
        AbsoluteFilePath(value=bad_value)
