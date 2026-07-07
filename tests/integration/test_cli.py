from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.config import Settings, get_settings
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import Severity
from sentinel.infrastructure.filesystem import _quarantine_ops
from sentinel.infrastructure.persistence.database import Base, Database
from sentinel.infrastructure.persistence.models.discovery import (
    CpanelAccountModel,
    ServerModel,
    WordPressInstallationModel,
)
from sentinel.infrastructure.persistence.models.integrity import IntegrityFindingModel

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    """`sentinel.config.get_settings` is process-wide `lru_cache`'d, so a
    test overriding `SENTINEL_MODE` via `CliRunner(..., env=...)` would
    otherwise see whatever Settings a prior test already cached."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _migrated_db_path(tmp_path: Path) -> Path:
    """Creates a schema-complete SQLite DB via `Base.metadata.create_all`,
    exactly as `tests/conftest.py`'s `database` fixture does for e2e tests —
    but synchronous, since CLI tests here don't use `pytest-asyncio`."""
    db_path = tmp_path / "cli-test.db"
    settings = Settings(environment="test", database_url=f"sqlite+aiosqlite:///{db_path}")
    database = Database(settings)

    async def _create_schema() -> None:
        async with database.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await database.dispose()

    asyncio.run(_create_schema())
    return db_path


def _seed_wordpress_installation(
    db_path: Path, *, absolute_path: Path, wp_version: str | None = "6.5"
) -> str:
    """Inserts a Server/CpanelAccount/WordPressInstallation row directly,
    synchronously, for CLI tests that don't use `pytest-asyncio`."""
    settings = Settings(environment="test", database_url=f"sqlite+aiosqlite:///{db_path}")
    database = Database(settings)
    installation_id = uuid4()

    async def _seed() -> None:
        now = utcnow()
        async with database.session() as session:
            server = ServerModel(
                id=uuid4(),
                hostname=f"host-{uuid4().hex}.example.com",
                os_info="Linux 6.1",
                agent_version="0.1.0",
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(server)
            await session.flush()

            account = CpanelAccountModel(
                id=uuid4(),
                server_id=server.id,
                username="examplebob",
                primary_domain="example.com",
                home_directory=str(absolute_path.parent),
                is_suspended=False,
                is_active=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(account)
            await session.flush()

            session.add(
                WordPressInstallationModel(
                    id=installation_id,
                    cpanel_account_id=account.id,
                    absolute_path=str(absolute_path),
                    domain="example.com",
                    wp_version=wp_version,
                    php_version="8.1",
                    is_multisite=False,
                    is_active=True,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()
        await database.dispose()

    asyncio.run(_seed())
    return str(installation_id)


def _seed_quarantined_finding(db_path: Path, *, home: Path, quarantine_root: Path) -> str:
    """Seeds an account plus an ``IntegrityFinding`` whose file has actually
    been moved into ``quarantine_root`` via the real ``_quarantine_ops``
    machinery — mirroring what ``QuarantineFindingUseCase`` does — so
    ``quarantine list/view/inspect`` and ``restore`` exercise real files on
    disk rather than a purely synthetic database row."""
    settings = Settings(environment="test", database_url=f"sqlite+aiosqlite:///{db_path}")
    database = Database(settings)
    finding_id = uuid4()

    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "shell.php"
    target.write_text("<?php system($_GET['c']); ?>")

    quarantined = _quarantine_ops.quarantine_file(
        target,
        quarantine_dir=quarantine_root / "examplebob",
        detection_reason="ADDED file change",
        severity=Severity.HIGH,
        detected_at=utcnow(),
    )

    async def _seed() -> None:
        now = utcnow()
        async with database.session() as session:
            server = ServerModel(
                id=uuid4(),
                hostname=f"host-{uuid4().hex}.example.com",
                os_info="Linux 6.1",
                agent_version="0.1.0",
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(server)
            await session.flush()

            account = CpanelAccountModel(
                id=uuid4(),
                server_id=server.id,
                username="examplebob",
                primary_domain="example.com",
                home_directory=str(home),
                is_suspended=False,
                is_active=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(account)
            await session.flush()

            session.add(
                IntegrityFindingModel(
                    id=finding_id,
                    account_id=account.id,
                    relative_path="public_html/shell.php",
                    change_type="ADDED",
                    severity="HIGH",
                    previous_sha256=None,
                    current_sha256=None,
                    is_acknowledged=False,
                    remediation_state="QUARANTINED",
                    quarantine_path=quarantined.quarantine_path,
                    quarantine_mode=quarantined.mode,
                    quarantine_size_bytes=quarantined.size_bytes,
                    quarantine_owner_uid=quarantined.owner_uid,
                    quarantine_owner_gid=quarantined.owner_gid,
                    detected_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()
        await database.dispose()

    asyncio.run(_seed())
    return str(finding_id)


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

    quarantine_result = runner.invoke(
        app, ["scan-archive", str(tmp_path), "--apply-quarantine"], env={"SENTINEL_MODE": "manual"}
    )
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

    result = runner.invoke(
        app,
        ["scan-archive", str(tmp_path), "--json", "--apply-quarantine"],
        env={"SENTINEL_MODE": "manual"},
    )

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


def test_doctor_passes_when_everything_is_configured(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app,
        ["doctor"],
        env={
            "SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SENTINEL_QUARANTINE_ROOT_DIRECTORY": str(tmp_path / "quarantine"),
        },
    )

    assert result.exit_code == 0
    assert "database: connected" in result.stdout


def test_doctor_fails_when_required_directory_is_missing(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app,
        ["doctor"],
        env={
            "SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SENTINEL_QUARANTINE_ROOT_DIRECTORY": str(tmp_path / "quarantine"),
            "SENTINEL_CPANEL_ETC_DIRECTORY": str(tmp_path / "does-not-exist"),
        },
    )

    assert result.exit_code == 1
    assert "[FAIL" in result.stdout


def test_health_reports_database_and_never_run_jobs(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app, ["health"], env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"}
    )

    assert result.exit_code == 0
    assert "database: connected" in result.stdout
    assert "NEVER_RUN" in result.stdout
    assert "queue: 0 unprocessed" in result.stdout


def test_status_reports_zero_counts_on_fresh_database(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app, ["status"], env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"}
    )

    assert result.exit_code == 0
    assert "(no jobs have run yet)" in result.stdout
    assert "0 total, 0 unprocessed" in result.stdout
    assert "0 integrity finding(s)" in result.stdout


def test_create_api_key_prints_plaintext_once_and_stores_only_hash(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app,
        ["create-api-key", "--name", "test-key"],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert "test-key" in result.stdout
    assert "Save this now" in result.stdout

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT name, key_hash, key_prefix FROM api_keys").fetchone()
    finally:
        conn.close()

    assert row is not None
    name, key_hash, key_prefix = row
    assert name == "test-key"
    assert len(key_hash) == 64
    assert key_hash not in result.stdout


def test_wp_inventory_reports_seeded_installation(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    site_root = tmp_path / "public_html"
    site_root.mkdir()
    installation_id = _seed_wordpress_installation(db_path, absolute_path=site_root)

    result = runner.invoke(
        app,
        ["wp", "inventory", "--installation-id", installation_id],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert installation_id in result.stdout
    assert "wp_version=6.5" in result.stdout
    assert "php_version=8.1" in result.stdout


def test_wp_integrity_reports_unknown_without_wp_version(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    site_root = tmp_path / "public_html"
    site_root.mkdir()
    installation_id = _seed_wordpress_installation(
        db_path, absolute_path=site_root, wp_version=None
    )

    result = runner.invoke(
        app,
        ["wp", "integrity", "--installation-id", installation_id],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert "UNKNOWN" in result.stdout


def test_wp_audit_flags_fake_plugin_and_exits_nonzero(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    site_root = tmp_path / "public_html"
    plugin_dir = site_root / "wp-content" / "plugins" / "totally-legit"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "index.php").write_text("<?php // no plugin header\n")
    installation_id = _seed_wordpress_installation(db_path, absolute_path=site_root)

    result = runner.invoke(
        app,
        ["wp", "audit", "--installation-id", installation_id],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 1
    assert "fake_plugin" in result.stdout


def test_wp_audit_reports_no_findings_for_clean_installation(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    site_root = tmp_path / "public_html"
    site_root.mkdir()
    installation_id = _seed_wordpress_installation(db_path, absolute_path=site_root)

    result = runner.invoke(
        app,
        ["wp", "audit", "--installation-id", installation_id],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert "No findings." in result.stdout


def test_quarantine_list_reports_none_when_empty(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app,
        ["quarantine", "list"],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert "No quarantined files." in result.stdout


def test_quarantine_list_shows_quarantined_finding(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    finding_id = _seed_quarantined_finding(
        db_path, home=tmp_path / "home" / "examplebob", quarantine_root=tmp_path / "quarantine"
    )

    result = runner.invoke(
        app,
        ["quarantine", "list"],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert finding_id in result.stdout
    assert "public_html/shell.php" in result.stdout
    assert "ADDED file change" in result.stdout
    assert "80" in result.stdout


def test_quarantine_view_shows_full_metadata(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    finding_id = _seed_quarantined_finding(
        db_path, home=tmp_path / "home" / "examplebob", quarantine_root=tmp_path / "quarantine"
    )

    result = runner.invoke(
        app,
        ["quarantine", "view", finding_id],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert f"ID:                {finding_id}" in result.stdout
    assert "Malware score:     80" in result.stdout
    assert "Quarantine metadata:" in result.stdout
    assert "detection_reason: ADDED file change" in result.stdout
    assert "original_path:" in result.stdout


def test_quarantine_view_unknown_id_exits_nonzero(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)

    result = runner.invoke(
        app,
        ["quarantine", "view", str(uuid4())],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 1


def test_quarantine_inspect_extracts_safe_read_only_copy(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    finding_id = _seed_quarantined_finding(
        db_path, home=tmp_path / "home" / "examplebob", quarantine_root=tmp_path / "quarantine"
    )

    result = runner.invoke(
        app,
        ["quarantine", "inspect", finding_id],
        env={"SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}"},
    )

    assert result.exit_code == 0
    assert "Safe copy extracted to:" in result.stdout
    assert "<?php system" in result.stdout

    copy_line = next(
        line for line in result.stdout.splitlines() if line.startswith("Safe copy extracted to:")
    )
    safe_copy = Path(copy_line.split("Safe copy extracted to:", 1)[1].strip())
    assert safe_copy.is_file()
    assert (safe_copy.stat().st_mode & 0o777) == 0o400


def test_restore_moves_file_back_after_confirmation(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    home = tmp_path / "home" / "examplebob"
    quarantine_root = tmp_path / "quarantine"
    finding_id = _seed_quarantined_finding(db_path, home=home, quarantine_root=quarantine_root)
    restored_file = home / "public_html" / "shell.php"

    result = runner.invoke(
        app,
        ["restore", finding_id, "--yes"],
        env={
            "SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SENTINEL_QUARANTINE_ROOT_DIRECTORY": str(quarantine_root),
            "SENTINEL_MODE": "manual",
        },
    )

    assert result.exit_code == 0
    assert restored_file.is_file()
    assert "Restored" in result.stdout


def test_restore_without_yes_prompts_and_aborts_on_no(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    home = tmp_path / "home" / "examplebob"
    quarantine_root = tmp_path / "quarantine"
    finding_id = _seed_quarantined_finding(db_path, home=home, quarantine_root=quarantine_root)
    restored_file = home / "public_html" / "shell.php"

    result = runner.invoke(
        app,
        ["restore", finding_id],
        input="n\n",
        env={
            "SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SENTINEL_QUARANTINE_ROOT_DIRECTORY": str(quarantine_root),
            "SENTINEL_MODE": "manual",
        },
    )

    assert result.exit_code == 1
    assert "Aborted" in result.stdout
    assert not restored_file.exists()


def test_restore_refused_in_observe_mode(tmp_path: Path) -> None:
    db_path = _migrated_db_path(tmp_path)
    home = tmp_path / "home" / "examplebob"
    quarantine_root = tmp_path / "quarantine"
    finding_id = _seed_quarantined_finding(db_path, home=home, quarantine_root=quarantine_root)

    result = runner.invoke(
        app,
        ["restore", finding_id, "--yes"],
        env={
            "SENTINEL_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SENTINEL_QUARANTINE_ROOT_DIRECTORY": str(quarantine_root),
            "SENTINEL_MODE": "observe",
        },
    )

    assert result.exit_code == 1
    assert "observe" in result.stderr
