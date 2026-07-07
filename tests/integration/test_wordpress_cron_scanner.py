from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.wordpress.cron_scanner import SystemCrontabScanner


def _account(username: str = "examplebob") -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value=username),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value=f"/home/{username}"),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


async def test_scan_parses_valid_crontab_lines(tmp_path: Path) -> None:
    account = _account()
    (tmp_path / account.username.value).write_text(
        "*/15 * * * * /usr/bin/php /home/examplebob/wp-cron.php\n"
        "0 0 * * * /usr/bin/php /home/examplebob/cleanup.php --flag value\n"
    )
    scanner = SystemCrontabScanner(crontab_directory=str(tmp_path))

    entries = await scanner.scan(account)

    assert len(entries) == 2
    assert entries[0].schedule_raw == "*/15 * * * *"
    assert entries[0].command == "/usr/bin/php /home/examplebob/wp-cron.php"
    assert entries[1].command == "/usr/bin/php /home/examplebob/cleanup.php --flag value"


async def test_scan_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    account = _account()
    (tmp_path / account.username.value).write_text("# a comment\n\n*/5 * * * * /usr/bin/true\n")
    scanner = SystemCrontabScanner(crontab_directory=str(tmp_path))

    entries = await scanner.scan(account)

    assert len(entries) == 1
    assert entries[0].command == "/usr/bin/true"


async def test_scan_skips_environment_variable_assignments(tmp_path: Path) -> None:
    account = _account()
    (tmp_path / account.username.value).write_text(
        "PATH=/usr/bin:/bin\nMAILTO=admin@example.com\n* * * * * /usr/bin/true\n"
    )
    scanner = SystemCrontabScanner(crontab_directory=str(tmp_path))

    entries = await scanner.scan(account)

    assert len(entries) == 1
    assert entries[0].command == "/usr/bin/true"


async def test_scan_returns_empty_list_when_crontab_missing(tmp_path: Path) -> None:
    account = _account()
    scanner = SystemCrontabScanner(crontab_directory=str(tmp_path))

    entries = await scanner.scan(account)

    assert entries == []
