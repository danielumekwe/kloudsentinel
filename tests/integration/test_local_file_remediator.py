from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import FileRemediationError
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity
from sentinel.infrastructure.filesystem.local_file_remediator import LocalFileRemediator


def _remediator(root: Path, quarantine: Path) -> LocalFileRemediator:
    return LocalFileRemediator(root_directory=root, quarantine_directory=quarantine)


async def test_quarantine_moves_file_into_incident_folder_out_of_root(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    (root / "wp-content").mkdir(parents=True)
    target = root / "wp-content" / "shell.php"
    target.write_text("<?php evil(); ?>")
    target.chmod(0o644)
    quarantine_dir = tmp_path / "quarantine"

    result = await _remediator(root, quarantine_dir).quarantine(
        relative_path=RelativeFilePath(value="wp-content/shell.php"),
        detection_reason="webshell-signature: matched",
        severity=Severity.CRITICAL,
        detected_at=utcnow(),
    )

    assert not target.exists()
    incident_dir = Path(result.quarantine_path)
    assert incident_dir.is_dir()
    assert incident_dir.parent == quarantine_dir
    assert (incident_dir / "shell.php").is_file()
    assert result.mode == "644"
    assert result.size_bytes == len("<?php evil(); ?>")


async def test_quarantine_missing_file_raises(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    quarantine_dir = tmp_path / "quarantine"

    with pytest.raises(FileRemediationError):
        await _remediator(root, quarantine_dir).quarantine(
            relative_path=RelativeFilePath(value="missing.php"),
            detection_reason="rule",
            severity=Severity.MEDIUM,
            detected_at=utcnow(),
        )


async def test_quarantine_rejects_path_escaping_root_via_symlinked_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "secret.php").write_text("<?php // not part of this archive ?>")
    (root / "uploads").symlink_to(outside, target_is_directory=True)
    quarantine_dir = tmp_path / "quarantine"

    with pytest.raises(FileRemediationError):
        await _remediator(root, quarantine_dir).quarantine(
            relative_path=RelativeFilePath(value="uploads/secret.php"),
            detection_reason="rule",
            severity=Severity.MEDIUM,
            detected_at=utcnow(),
        )
    assert (outside / "secret.php").exists()


async def test_restore_rejects_quarantine_path_outside_quarantine_root(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    rogue_file = tmp_path / "rogue.php"
    rogue_file.write_text("<?php // not actually quarantined ?>")

    with pytest.raises(FileRemediationError):
        await _remediator(root, tmp_path / "quarantine").restore(
            relative_path=RelativeFilePath(value="shell.php"),
            quarantine_path=str(rogue_file),
            mode="644",
        )
    assert rogue_file.exists()


async def test_restore_puts_file_back_with_original_mode(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    (root / "wp-content").mkdir(parents=True)
    target = root / "wp-content" / "shell.php"
    target.write_text("<?php evil(); ?>")
    quarantine_dir = tmp_path / "quarantine"
    remediator = _remediator(root, quarantine_dir)

    quarantined = await remediator.quarantine(
        relative_path=RelativeFilePath(value="wp-content/shell.php"),
        detection_reason="rule",
        severity=Severity.MEDIUM,
        detected_at=utcnow(),
    )
    await remediator.restore(
        relative_path=RelativeFilePath(value="wp-content/shell.php"),
        quarantine_path=quarantined.quarantine_path,
        mode=quarantined.mode,
    )

    assert target.is_file()
    assert not Path(quarantined.quarantine_path).exists()
    assert format(target.stat().st_mode & 0o777, "03o") == quarantined.mode


async def test_purge_deletes_quarantine_folder(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    (root / "wp-content").mkdir(parents=True)
    target = root / "wp-content" / "shell.php"
    target.write_text("<?php evil(); ?>")
    quarantine_dir = tmp_path / "quarantine"
    remediator = _remediator(root, quarantine_dir)

    quarantined = await remediator.quarantine(
        relative_path=RelativeFilePath(value="wp-content/shell.php"),
        detection_reason="rule",
        severity=Severity.MEDIUM,
        detected_at=utcnow(),
    )
    await remediator.purge(quarantine_path=quarantined.quarantine_path)

    assert not Path(quarantined.quarantine_path).exists()
