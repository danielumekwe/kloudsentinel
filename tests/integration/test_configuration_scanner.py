from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.wordpress.configuration_scanner import (
    FilesystemWordPressConfigurationScanner,
)


def _installation(path: Path) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=uuid4(),
        absolute_path=AbsoluteFilePath(value=str(path)),
        domain=DomainName(value="example.com"),
        wp_version="6.4.0",
        is_multisite=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _wp_config(
    *, debug: bool = False, disallow_file_edit: bool = True, prefix: str = "mywp_"
) -> str:
    lines = [
        f"define( 'WP_DEBUG', {'true' if debug else 'false'} );",
        f"define( 'DISALLOW_FILE_MODS', {'true' if disallow_file_edit else 'false'} );",
        f"define( 'DISALLOW_FILE_EDIT', {'true' if disallow_file_edit else 'false'} );",
        "define( 'FORCE_SSL_ADMIN', true );",
        f"$table_prefix = '{prefix}';",
    ]
    return "\n".join(lines)


@pytest.fixture()
def wp_root(tmp_path: Path) -> Path:
    return tmp_path


async def test_wp_config_debug_true_is_flagged(wp_root: Path) -> None:
    (wp_root / "wp-config.php").write_text(_wp_config(debug=True))
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    debug_item = next(i for i in items if i.key == "WP_DEBUG")
    assert debug_item.is_flagged is True
    assert debug_item.raw_value == "true"


async def test_wp_config_debug_false_is_not_flagged(wp_root: Path) -> None:
    (wp_root / "wp-config.php").write_text(_wp_config(debug=False))
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    debug_item = next(i for i in items if i.key == "WP_DEBUG")
    assert debug_item.is_flagged is False


async def test_disallow_file_edit_absent_is_flagged(wp_root: Path) -> None:
    # Write a config that does NOT define DISALLOW_FILE_EDIT
    (wp_root / "wp-config.php").write_text("define('WP_DEBUG', false);\n$table_prefix = 'wp_';")
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    item = next(i for i in items if i.key == "DISALLOW_FILE_EDIT")
    assert item.is_flagged is True
    assert item.raw_value is None


async def test_disallow_file_edit_true_is_not_flagged(wp_root: Path) -> None:
    (wp_root / "wp-config.php").write_text(_wp_config(disallow_file_edit=True))
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    item = next(i for i in items if i.key == "DISALLOW_FILE_EDIT")
    assert item.is_flagged is False


async def test_default_table_prefix_is_flagged(wp_root: Path) -> None:
    (wp_root / "wp-config.php").write_text("$table_prefix = 'wp_';")
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    item = next(i for i in items if i.key == "table_prefix")
    assert item.is_flagged is True
    assert item.raw_value == "wp_"


async def test_custom_table_prefix_is_not_flagged(wp_root: Path) -> None:
    (wp_root / "wp-config.php").write_text("$table_prefix = 'mysite_';")
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    item = next(i for i in items if i.key == "table_prefix")
    assert item.is_flagged is False


async def test_missing_wp_config_returns_empty_list(wp_root: Path) -> None:
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    wp_config_items = [i for i in items if i.config_source == "wp-config.php"]
    assert wp_config_items == []


async def test_user_ini_display_errors_on_is_flagged(wp_root: Path) -> None:
    (wp_root / ".user.ini").write_text("display_errors = On\n")
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    item = next(i for i in items if i.key == "display_errors")
    assert item.is_flagged is True
    assert item.config_source == ".user.ini"


async def test_user_ini_display_errors_off_is_not_flagged(wp_root: Path) -> None:
    (wp_root / ".user.ini").write_text("display_errors = Off\n")
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    item = next(i for i in items if i.key == "display_errors")
    assert item.is_flagged is False


async def test_missing_user_ini_returns_no_ini_items(wp_root: Path) -> None:
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    ini_items = [i for i in items if i.config_source == ".user.ini"]
    assert ini_items == []


async def test_allow_url_include_flagged(wp_root: Path) -> None:
    (wp_root / ".user.ini").write_text("allow_url_include = 1\nallow_url_fopen = On\n")
    scanner = FilesystemWordPressConfigurationScanner()

    items = await scanner.scan(_installation(wp_root))

    include_item = next(i for i in items if i.key == "allow_url_include")
    fopen_item = next(i for i in items if i.key == "allow_url_fopen")
    assert include_item.is_flagged is True
    assert fopen_item.is_flagged is True
