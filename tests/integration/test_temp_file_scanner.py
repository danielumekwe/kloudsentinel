from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.forensics.value_objects import TempFileVerdict
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.forensics.temp_file_scanner import FilesystemTempFileScanner
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner


class FakeCpanelAccountRepository:
    def __init__(self, accounts: list[CpanelAccount] | None = None) -> None:
        self.by_id: dict[UUID, CpanelAccount] = {a.id: a for a in accounts or []}

    async def add(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> CpanelAccount | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CpanelAccount]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_username(self, username: LinuxUsername) -> CpanelAccount | None:
        return next((a for a in self.by_id.values() if a.username == username), None)

    async def list_by_server(self, server_id: UUID) -> list[CpanelAccount]:
        return [a for a in self.by_id.values() if a.server_id == server_id]


def _account(username: str) -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value=username),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value=f"/home/{username}"),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _scanner(
    tmp_path: Path, *, accounts: list[CpanelAccount] | None = None
) -> FilesystemTempFileScanner:
    return FilesystemTempFileScanner(
        directories=[str(tmp_path)],
        watched_extensions=[".php", ".pl", ".cgi", ".sh"],
        php_malware_scanner=PhpMalwareScanner(),
        account_repository=FakeCpanelAccountRepository(accounts),
    )


async def test_webshell_dropped_in_temp_dir_is_flagged_malicious(tmp_path: Path) -> None:
    (tmp_path / "update_abc.php").write_text("<?php system($_GET['cmd']); ?>")

    observations = await _scanner(tmp_path).scan()

    assert len(observations) == 1
    (observation,) = observations
    assert observation.verdict is TempFileVerdict.MALICIOUS
    assert "rce-user-input" in observation.matched_rule_ids
    assert observation.sha256 is not None


async def test_benign_script_is_flagged_legitimate(tmp_path: Path) -> None:
    (tmp_path / "cleanup.sh").write_text("#!/bin/sh\necho hello\n")

    observations = await _scanner(tmp_path).scan()

    assert len(observations) == 1
    assert observations[0].verdict is TempFileVerdict.LEGITIMATE


async def test_unwatched_extension_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("system($_GET['cmd']);")

    observations = await _scanner(tmp_path).scan()

    assert observations == []


async def test_resolve_account_id_matches_known_username(tmp_path: Path) -> None:
    account = _account("examplebob")
    scanner = _scanner(tmp_path, accounts=[account])

    resolved = await scanner._resolve_account("examplebob")

    assert resolved is not None
    assert resolved.id == account.id


async def test_resolve_account_id_returns_none_for_unknown_username(tmp_path: Path) -> None:
    scanner = _scanner(tmp_path)

    resolved = await scanner._resolve_account("examplebob")

    assert resolved is None


async def test_resolve_account_id_returns_none_for_invalid_username_shape(tmp_path: Path) -> None:
    """Usernames like ``www-data`` or ``nobody`` won't validate as a
    ``LinuxUsername`` (hyphens aren't allowed) — the scanner must treat that
    as "no matching account" rather than raising."""
    scanner = _scanner(tmp_path)

    resolved = await scanner._resolve_account("www-data")

    assert resolved is None


async def test_scan_across_multiple_directories(tmp_path: Path) -> None:
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "one.php").write_text("<?php echo 'hi'; ?>")
    (dir_b / "two.php").write_text("<?php /* FilesMan */ ?>")

    scanner = FilesystemTempFileScanner(
        directories=[str(dir_a), str(dir_b)],
        watched_extensions=[".php"],
        php_malware_scanner=PhpMalwareScanner(),
        account_repository=FakeCpanelAccountRepository(),
    )

    observations = await scanner.scan()

    assert len(observations) == 2
    verdicts = {str(o.absolute_path): o.verdict for o in observations}
    assert verdicts[str(dir_a / "one.php")] is TempFileVerdict.LEGITIMATE
    assert verdicts[str(dir_b / "two.php")] is TempFileVerdict.MALICIOUS


async def test_missing_directory_is_skipped_without_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    scanner = FilesystemTempFileScanner(
        directories=[str(missing)],
        watched_extensions=[".php"],
        php_malware_scanner=PhpMalwareScanner(),
        account_repository=FakeCpanelAccountRepository(),
    )

    observations = await scanner.scan()

    assert observations == []
