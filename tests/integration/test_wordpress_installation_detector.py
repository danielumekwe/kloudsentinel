from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.wordpress.installation_detector import FilesystemWordPressDetector


def _account(home_directory: Path) -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value=str(home_directory)),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _plant_wordpress(root: Path, *, wp_version: str = "6.5") -> None:
    wp_includes = root / "wp-includes"
    wp_includes.mkdir(parents=True)
    (wp_includes / "version.php").write_text(f"<?php\n$wp_version = '{wp_version}';\n")


async def test_detects_real_installation_under_public_html(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    account = _account(home)

    findings = await FilesystemWordPressDetector().detect(account)

    assert len(findings) == 1
    finding = findings[0]
    assert str(finding.absolute_path) == str(home / "public_html")
    assert finding.wp_version == "6.5"
    assert finding.domain == account.primary_domain


async def test_ignores_backup_directory_copy(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    _plant_wordpress(home / "public_html_backup")
    account = _account(home)

    findings = await FilesystemWordPressDetector().detect(account)

    paths = {str(f.absolute_path) for f in findings}
    assert str(home / "public_html") in paths
    assert str(home / "public_html_backup") not in paths
    assert len(findings) == 1


async def test_ignores_trash_directory_copy(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    _plant_wordpress(home / ".trash" / "public_html")
    account = _account(home)

    findings = await FilesystemWordPressDetector().detect(account)

    assert len(findings) == 1


async def test_ignores_virtfs_directory_copy(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    _plant_wordpress(home / "virtfs" / "public_html")
    account = _account(home)

    findings = await FilesystemWordPressDetector().detect(account)

    assert len(findings) == 1


async def test_custom_excluded_markers_are_respected(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    _plant_wordpress(home / "staging_site")
    account = _account(home)

    detector = FilesystemWordPressDetector(excluded_directory_markers=("staging",))
    findings = await detector.detect(account)

    paths = {str(f.absolute_path) for f in findings}
    assert str(home / "staging_site") not in paths


async def test_php_version_detected_from_htaccess_handler(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    (home / "public_html" / ".htaccess").write_text(
        "AddHandler application/x-httpd-ea-php81 .php\n"
    )
    account = _account(home)

    findings = await FilesystemWordPressDetector().detect(account)

    assert findings[0].php_version == "8.1"


async def test_php_version_is_none_without_htaccess(tmp_path: Path) -> None:
    home = tmp_path
    _plant_wordpress(home / "public_html")
    account = _account(home)

    findings = await FilesystemWordPressDetector().detect(account)

    assert findings[0].php_version is None


async def test_returns_empty_list_when_account_home_missing(tmp_path: Path) -> None:
    account = _account(tmp_path / "does-not-exist")

    findings = await FilesystemWordPressDetector().detect(account)

    assert findings == []
