from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.wordpress.installation_detector import FilesystemWordPressDetector

_VERSION_PHP = "<?php\n$wp_version = '6.5.2';\n"
_MULTISITE_CONFIG = "<?php\ndefine( 'MULTISITE', true );\n"
_SINGLE_CONFIG = "<?php\n// no multisite here\n"


def _account(home: Path, domain: str = "example.com") -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob"),
        primary_domain=DomainName(value=domain),
        home_directory=AbsoluteFilePath(value=str(home)),
        is_suspended=False,
        last_seen_at=utcnow(),
    )


def _write_install(root: Path, *, multisite: bool = False) -> None:
    (root / "wp-includes").mkdir(parents=True)
    (root / "wp-includes" / "version.php").write_text(_VERSION_PHP)
    (root / "wp-config.php").write_text(_MULTISITE_CONFIG if multisite else _SINGLE_CONFIG)


async def test_detect_returns_empty_when_home_missing(tmp_path: Path) -> None:
    detector = FilesystemWordPressDetector()
    account = _account(tmp_path / "does-not-exist")
    assert await detector.detect(account) == []


async def test_detect_finds_install_in_public_html_and_attributes_primary_domain(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home" / "examplebob"
    _write_install(home / "public_html")

    detector = FilesystemWordPressDetector()
    findings = await detector.detect(_account(home))

    assert len(findings) == 1
    finding = findings[0]
    assert str(finding.absolute_path) == str(home / "public_html")
    assert finding.wp_version == "6.5.2"
    assert finding.is_multisite is False
    assert str(finding.domain) == "example.com"


async def test_detect_leaves_domain_none_for_subdirectory_install(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    _write_install(home / "public_html" / "blog")

    detector = FilesystemWordPressDetector()
    findings = await detector.detect(_account(home))

    assert len(findings) == 1
    assert findings[0].domain is None


async def test_detect_reports_multisite(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    _write_install(home / "public_html", multisite=True)

    detector = FilesystemWordPressDetector()
    findings = await detector.detect(_account(home))

    assert findings[0].is_multisite is True


async def test_detect_does_not_descend_into_symlinked_directories(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    real_target = tmp_path / "elsewhere"
    _write_install(real_target)
    home.mkdir(parents=True)
    (home / "public_html").symlink_to(real_target, target_is_directory=True)

    detector = FilesystemWordPressDetector()
    findings = await detector.detect(_account(home))

    assert findings == []


async def test_detect_respects_max_depth(tmp_path: Path) -> None:
    home = tmp_path / "home" / "examplebob"
    deep_root = home / "a" / "b" / "c" / "d" / "e"
    _write_install(deep_root)

    detector = FilesystemWordPressDetector(max_depth=2)
    findings = await detector.detect(_account(home))

    assert findings == []
