from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import FileRemediationError
from sentinel.domain.shared.value_objects import (
    AbsoluteFilePath,
    DomainName,
    RelativeFilePath,
    Severity,
)
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator


def _account(home: Path) -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob1"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value=str(home)),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _remediator(quarantine_root: Path) -> FilesystemFileRemediator:
    return FilesystemFileRemediator(quarantine_root_directory=str(quarantine_root))


async def test_quarantine_moves_file_into_per_incident_folder(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob1"
    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "shell.php"
    target.write_text("<?php evil(); ?>")
    target.chmod(0o644)
    quarantine_root = tmp_path / "quarantine"
    account = _account(home)

    result = await _remediator(quarantine_root).quarantine(
        account=account,
        relative_path=RelativeFilePath(value="public_html/shell.php"),
        detection_reason="MODIFIED file change",
        severity=Severity.HIGH,
        detected_at=utcnow(),
    )

    assert not target.exists()
    incident_dir = Path(result.quarantine_path)
    assert incident_dir.is_dir()
    assert incident_dir.parent == quarantine_root / "examplebob1"
    assert (incident_dir / "shell.php").is_file()
    assert result.mode == "644"
    assert result.size_bytes == len("<?php evil(); ?>")
    assert isinstance(result.owner_uid, int)
    assert isinstance(result.owner_gid, int)

    metadata = json.loads((incident_dir / "metadata.json").read_text())
    assert metadata["detection_reason"] == "MODIFIED file change"
    assert metadata["severity"] == "HIGH"
    assert metadata["malware_score"] == 80
    assert metadata["original_path"] == str(target)
    assert len(metadata["sha256"]) == 64


async def test_quarantine_missing_file_raises(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob1"
    home.mkdir(parents=True)
    account = _account(home)

    with pytest.raises(FileRemediationError):
        await _remediator(tmp_path / "quarantine").quarantine(
            account=account,
            relative_path=RelativeFilePath(value="missing.php"),
            detection_reason="ADDED file change",
            severity=Severity.MEDIUM,
            detected_at=utcnow(),
        )


async def test_quarantine_rejects_symlink(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob1"
    home.mkdir(parents=True)
    real_file = tmp_path / "outside.php"
    real_file.write_text("<?php evil(); ?>")
    (home / "link.php").symlink_to(real_file)
    account = _account(home)

    with pytest.raises(FileRemediationError):
        await _remediator(tmp_path / "quarantine").quarantine(
            account=account,
            relative_path=RelativeFilePath(value="link.php"),
            detection_reason="ADDED file change",
            severity=Severity.MEDIUM,
            detected_at=utcnow(),
        )
    assert real_file.exists()


async def test_quarantine_rejects_path_escaping_home_via_symlinked_directory(
    tmp_path: Path,
) -> None:
    """A ``RelativeFilePath`` can't spell ``..`` in its segments, but an
    account whose filesystem has been tampered with could still replace an
    intermediate directory with a symlink pointing outside its home. The
    remediator must refuse to follow it rather than quarantine/restore a
    file elsewhere on the server."""
    home = tmp_path / "home" / "examplebob1"
    home.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "secret.php").write_text("<?php // not this account's file ?>")
    (home / "uploads").symlink_to(outside, target_is_directory=True)
    account = _account(home)

    with pytest.raises(FileRemediationError):
        await _remediator(tmp_path / "quarantine").quarantine(
            account=account,
            relative_path=RelativeFilePath(value="uploads/secret.php"),
            detection_reason="ADDED file change",
            severity=Severity.MEDIUM,
            detected_at=utcnow(),
        )
    assert (outside / "secret.php").exists()


async def test_restore_puts_file_back_with_original_mode_and_owner(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob1"
    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "shell.php"
    target.write_text("<?php evil(); ?>")
    quarantine_root = tmp_path / "quarantine"
    account = _account(home)
    remediator = _remediator(quarantine_root)

    quarantined = await remediator.quarantine(
        account=account,
        relative_path=RelativeFilePath(value="public_html/shell.php"),
        detection_reason="ADDED file change",
        severity=Severity.MEDIUM,
        detected_at=utcnow(),
    )
    await remediator.restore(
        account=account,
        relative_path=RelativeFilePath(value="public_html/shell.php"),
        quarantine_path=quarantined.quarantine_path,
        mode=quarantined.mode,
        owner_uid=quarantined.owner_uid,
        owner_gid=quarantined.owner_gid,
    )

    assert target.is_file()
    assert not Path(quarantined.quarantine_path).exists()
    assert format(target.stat().st_mode & 0o777, "03o") == quarantined.mode


async def test_restore_rejects_quarantine_path_outside_quarantine_root(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob1"
    home.mkdir(parents=True)
    account = _account(home)
    rogue_file = tmp_path / "rogue.php"
    rogue_file.write_text("<?php // not actually quarantined ?>")

    with pytest.raises(FileRemediationError):
        await _remediator(tmp_path / "quarantine").restore(
            account=account,
            relative_path=RelativeFilePath(value="public_html/shell.php"),
            quarantine_path=str(rogue_file),
            mode="644",
            owner_uid=None,
            owner_gid=None,
        )
    assert rogue_file.exists()


async def test_purge_deletes_quarantine_folder(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob1"
    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "shell.php"
    target.write_text("<?php evil(); ?>")
    quarantine_root = tmp_path / "quarantine"
    account = _account(home)
    remediator = _remediator(quarantine_root)

    quarantined = await remediator.quarantine(
        account=account,
        relative_path=RelativeFilePath(value="public_html/shell.php"),
        detection_reason="ADDED file change",
        severity=Severity.MEDIUM,
        detected_at=utcnow(),
    )
    await remediator.purge(quarantine_path=quarantined.quarantine_path)

    assert not Path(quarantined.quarantine_path).exists()


async def test_purge_rejects_path_outside_quarantine_root(tmp_path: Path) -> None:
    rogue_file = tmp_path / "rogue.php"
    rogue_file.write_text("<?php // not actually quarantined ?>")

    with pytest.raises(FileRemediationError):
        await _remediator(tmp_path / "quarantine").purge(quarantine_path=str(rogue_file))
    assert rogue_file.exists()
