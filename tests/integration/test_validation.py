from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.config import Settings
from sentinel.infrastructure.validation import (
    check_configuration,
    check_database_connectivity,
    check_directory_readable,
    check_directory_writable,
    check_whm_plugin_registration,
    has_critical_failures,
    has_failures,
    host_directory_checks,
)


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        "cpanel_etc_directory": str(tmp_path / "etc"),
        "cpanel_home_base_directory": str(tmp_path / "home"),
        "quarantine_root_directory": str(tmp_path / "quarantine"),
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_check_directory_readable_passes_for_existing_directory(tmp_path: Path) -> None:
    result = check_directory_readable("etc", str(tmp_path), required=True)

    assert result.status == "PASS"


def test_check_directory_readable_fails_when_required_and_missing(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    result = check_directory_readable("etc", str(missing), required=True)

    assert result.status == "FAIL"


def test_check_directory_readable_warns_when_optional_and_missing(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    result = check_directory_readable("proc", str(missing), required=False)

    assert result.status == "WARN"


def test_check_directory_writable_creates_missing_directory(tmp_path: Path) -> None:
    target = tmp_path / "quarantine"

    result = check_directory_writable("quarantine_root_directory", str(target))

    assert result.status == "PASS"
    assert target.is_dir()


def test_check_configuration_fails_when_quarantine_nested_under_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    settings = _settings(
        tmp_path,
        cpanel_home_base_directory=str(home),
        quarantine_root_directory=str(home / "quarantine"),
    )

    result = check_configuration(settings)

    assert result.status == "FAIL"


def test_check_configuration_passes_when_quarantine_is_separate(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    settings = _settings(tmp_path)

    result = check_configuration(settings)

    assert result.status == "PASS"


def test_host_directory_checks_marks_etc_and_home_as_required(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    results = host_directory_checks(settings)

    required_names = {"etc", "home"}
    for result in results:
        if result.name in required_names:
            assert result.status == "FAIL"


async def test_check_database_connectivity_passes_for_valid_url(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    result = await check_database_connectivity(settings)

    assert result.status == "PASS"


def test_check_whm_plugin_registration_is_none_when_no_cpanel_present() -> None:
    # Genuinely true on any non-WHM dev/CI machine — no mocking needed for
    # the primary, "not applicable" case this check is designed to skip.
    assert check_whm_plugin_registration() is None


def test_check_whm_plugin_registration_warns_when_not_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Path, "is_dir", lambda self: str(self) == "/usr/local/cpanel")
    monkeypatch.setattr(Path, "is_file", lambda self: False)

    result = check_whm_plugin_registration()

    assert result is not None
    assert result.status == "WARN"


def test_check_whm_plugin_registration_passes_when_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Path, "is_dir", lambda self: str(self) == "/usr/local/cpanel")
    monkeypatch.setattr(Path, "is_file", lambda self: True)

    result = check_whm_plugin_registration()

    assert result is not None
    assert result.status == "PASS"


def test_has_failures_true_when_any_check_failed() -> None:
    settings_results = [
        check_directory_readable("etc", "/does-not-exist", required=True),
        check_directory_readable("home", "/", required=True),
    ]

    assert has_failures(settings_results) is True


def test_has_critical_failures_ignores_non_critical_names(tmp_path: Path) -> None:
    results = [
        check_directory_readable("proc", str(tmp_path / "missing"), required=False),
    ]
    # WARN, not FAIL, and even a FAIL on a non-critical name shouldn't count:
    results.append(
        check_directory_readable("temp_dir:/tmp", str(tmp_path / "missing"), required=False)
    )

    assert has_critical_failures(results) is False
