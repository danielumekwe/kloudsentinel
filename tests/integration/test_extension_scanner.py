from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.wordpress.extension_scanner import FilesystemWordPressExtensionScanner

_PLUGIN_HEADER = """\
<?php
/**
 * Plugin Name: WooCommerce
 * Version: 8.0.0
 * Description: A plugin.
 */
"""

_PLUGIN_HEADER_NON_CONVENTIONAL = """\
<?php
/**
 * Plugin Name: Jetpack
 * Version: 12.5
 */
"""

_THEME_STYLE = """\
/*
Theme Name: Twenty Twenty-Four
Version: 1.1.0
Author: WordPress
*/
"""


def _installation(wp_root: Path) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=uuid4(),
        absolute_path=AbsoluteFilePath(value=str(wp_root)),
        domain=DomainName(value="example.com"),
        wp_version="6.4.0",
        is_multisite=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _scanner() -> FilesystemWordPressExtensionScanner:
    return FilesystemWordPressExtensionScanner()


async def test_scan_plugins_returns_empty_when_directory_missing(tmp_path: Path) -> None:
    installation = _installation(tmp_path)
    scanner = _scanner()

    result = await scanner.scan_plugins(installation)

    assert result == []


async def test_scan_themes_returns_empty_when_directory_missing(tmp_path: Path) -> None:
    installation = _installation(tmp_path)
    scanner = _scanner()

    result = await scanner.scan_themes(installation)

    assert result == []


async def test_scan_plugins_detects_conventional_main_file(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "wp-content" / "plugins"
    plugin_dir = plugins_dir / "woocommerce"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "woocommerce.php").write_text(_PLUGIN_HEADER)

    installation = _installation(tmp_path)
    result = await _scanner().scan_plugins(installation)

    assert len(result) == 1
    assert result[0].slug == "woocommerce"
    assert result[0].name == "WooCommerce"
    assert result[0].version == "8.0.0"


async def test_scan_plugins_detects_non_conventional_main_file(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "wp-content" / "plugins"
    plugin_dir = plugins_dir / "jetpack"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "jetpack-main.php").write_text(_PLUGIN_HEADER_NON_CONVENTIONAL)

    installation = _installation(tmp_path)
    result = await _scanner().scan_plugins(installation)

    assert len(result) == 1
    assert result[0].slug == "jetpack"
    assert result[0].name == "Jetpack"
    assert result[0].version == "12.5"


async def test_scan_plugins_skips_directory_with_no_plugin_header(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "wp-content" / "plugins"
    plugin_dir = plugins_dir / "not-a-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "not-a-plugin.php").write_text("<?php // no header here\n")

    installation = _installation(tmp_path)
    result = await _scanner().scan_plugins(installation)

    assert result == []


async def test_scan_plugins_skips_symlinks(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "wp-content" / "plugins"
    plugins_dir.mkdir(parents=True)
    real_dir = tmp_path / "real-plugin"
    real_dir.mkdir()
    (real_dir / "real-plugin.php").write_text(_PLUGIN_HEADER)
    (plugins_dir / "symlinked-plugin").symlink_to(real_dir)

    installation = _installation(tmp_path)
    result = await _scanner().scan_plugins(installation)

    assert result == []


async def test_scan_themes_detects_theme_with_style_css(tmp_path: Path) -> None:
    themes_dir = tmp_path / "wp-content" / "themes"
    theme_dir = themes_dir / "twentytwentyfour"
    theme_dir.mkdir(parents=True)
    (theme_dir / "style.css").write_text(_THEME_STYLE)

    installation = _installation(tmp_path)
    result = await _scanner().scan_themes(installation)

    assert len(result) == 1
    assert result[0].slug == "twentytwentyfour"
    assert result[0].name == "Twenty Twenty-Four"
    assert result[0].version == "1.1.0"


async def test_scan_themes_skips_directory_without_style_css(tmp_path: Path) -> None:
    themes_dir = tmp_path / "wp-content" / "themes"
    theme_dir = themes_dir / "incomplete-theme"
    theme_dir.mkdir(parents=True)
    (theme_dir / "functions.php").write_text("<?php\n")

    installation = _installation(tmp_path)
    result = await _scanner().scan_themes(installation)

    assert result == []


async def test_scan_themes_skips_symlinks(tmp_path: Path) -> None:
    themes_dir = tmp_path / "wp-content" / "themes"
    themes_dir.mkdir(parents=True)
    real_dir = tmp_path / "real-theme"
    real_dir.mkdir()
    (real_dir / "style.css").write_text(_THEME_STYLE)
    (themes_dir / "symlinked-theme").symlink_to(real_dir)

    installation = _installation(tmp_path)
    result = await _scanner().scan_themes(installation)

    assert result == []


async def test_scan_plugins_version_may_be_none(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "wp-content" / "plugins"
    plugin_dir = plugins_dir / "minimal"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "minimal.php").write_text("<?php\n/**\n * Plugin Name: Minimal Plugin\n */\n")

    installation = _installation(tmp_path)
    result = await _scanner().scan_plugins(installation)

    assert len(result) == 1
    assert result[0].name == "Minimal Plugin"
    assert result[0].version is None
