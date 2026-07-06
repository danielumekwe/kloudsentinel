from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sentinel.cli import app

runner = CliRunner()


def _plant_backdoor(root: Path) -> None:
    uploads = root / "wp-content" / "uploads" / "2024" / "01"
    uploads.mkdir(parents=True)
    (uploads / "avatar.php").write_text("<?php system($_GET['cmd']); ?>")
    (root / "index.php").write_text("<?php echo 'hello world'; ?>")


def test_scan_archive_reports_findings_without_moving_files(tmp_path: Path) -> None:
    _plant_backdoor(tmp_path)

    result = runner.invoke(app, ["scan-archive", str(tmp_path)])

    assert result.exit_code == 0
    assert "rce-user-input" in result.stdout
    assert "php-in-uploads" in result.stdout
    assert (tmp_path / "wp-content" / "uploads" / "2024" / "01" / "avatar.php").is_file()


def test_scan_archive_apply_quarantine_moves_file_and_rescan_is_clean(tmp_path: Path) -> None:
    _plant_backdoor(tmp_path)
    target = tmp_path / "wp-content" / "uploads" / "2024" / "01" / "avatar.php"

    quarantine_result = runner.invoke(app, ["scan-archive", str(tmp_path), "--apply-quarantine"])
    assert quarantine_result.exit_code == 0
    assert not target.exists()

    # Regression guard: the default quarantine directory must live outside
    # the scanned root, or a rescan would walk into it and re-flag the
    # files it just moved out of place.
    rescan_result = runner.invoke(app, ["scan-archive", str(tmp_path)])

    assert rescan_result.exit_code == 0
    assert "No findings" in rescan_result.stdout


def test_scan_archive_json_output_is_valid_json(tmp_path: Path) -> None:
    _plant_backdoor(tmp_path)

    result = runner.invoke(app, ["scan-archive", str(tmp_path), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["affected_files"] == 1
    assert any(f["rule_id"] == "rce-user-input" for f in payload["findings"])


def test_scan_archive_json_and_apply_quarantine_together_stays_valid_json(tmp_path: Path) -> None:
    _plant_backdoor(tmp_path)

    result = runner.invoke(app, ["scan-archive", str(tmp_path), "--json", "--apply-quarantine"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["quarantine_attempts"]
    assert all(attempt["succeeded"] for attempt in payload["quarantine_attempts"])


def test_scan_archive_rejects_non_directory(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    result = runner.invoke(app, ["scan-archive", str(missing)])

    assert result.exit_code == 1


def test_scan_archive_rejects_invalid_min_severity(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan-archive", str(tmp_path), "--min-severity", "NOPE"])

    assert result.exit_code == 1
