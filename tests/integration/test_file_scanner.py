from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.filesystem.file_scanner import FilesystemFileScanner


def _account(home: Path) -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value=str(home)),
        is_suspended=False,
        last_seen_at=utcnow(),
    )


def _scanner(
    *, excluded: list[str] | None = None, max_size: int = 26_214_400
) -> FilesystemFileScanner:
    return FilesystemFileScanner(
        excluded_relative_paths=excluded or [], max_file_size_bytes=max_size
    )


async def test_scan_returns_empty_when_home_missing(tmp_path: Path) -> None:
    scanner = _scanner()
    account = _account(tmp_path / "does-not-exist")
    assert await scanner.scan(account) == []


async def test_scan_hashes_files_and_captures_mode(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    home.mkdir(parents=True)
    target = home / "public_html" / "index.php"
    target.parent.mkdir(parents=True)
    content = b"<?php echo 'hi'; ?>"
    target.write_bytes(content)
    target.chmod(0o644)

    scanner = _scanner()
    findings = await scanner.scan(_account(home))

    assert len(findings) == 1
    finding = findings[0]
    assert str(finding.relative_path) == "public_html/index.php"
    assert str(finding.sha256) == hashlib.sha256(content).hexdigest()
    assert finding.size_bytes == len(content)
    assert finding.mode == "644"


async def test_scan_excludes_paths_matching_configured_substrings(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    (home / "public_html" / "wp-content" / "uploads").mkdir(parents=True)
    (home / "public_html" / "wp-content" / "uploads" / "photo.jpg").write_bytes(b"binary")
    (home / "mail" / "inbox").mkdir(parents=True)
    (home / "mail" / "inbox" / "1").write_text("email")
    (home / "public_html" / "index.php").write_text("<?php ?>")

    scanner = _scanner(excluded=["mail", "wp-content/uploads"])
    findings = await scanner.scan(_account(home))

    paths = {str(f.relative_path) for f in findings}
    assert paths == {"public_html/index.php"}


async def test_scan_skips_files_over_max_size(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    home.mkdir(parents=True)
    (home / "big.log").write_bytes(b"x" * 100)
    (home / "small.txt").write_bytes(b"y" * 10)

    scanner = _scanner(max_size=50)
    findings = await scanner.scan(_account(home))

    paths = {str(f.relative_path) for f in findings}
    assert paths == {"small.txt"}


async def test_scan_does_not_descend_into_symlinked_directories(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    real_target = tmp_path / "elsewhere"
    real_target.mkdir(parents=True)
    (real_target / "secret.txt").write_text("hidden")
    home.mkdir(parents=True)
    (home / "linked").symlink_to(real_target, target_is_directory=True)

    scanner = _scanner()
    findings = await scanner.scan(_account(home))

    assert findings == []
