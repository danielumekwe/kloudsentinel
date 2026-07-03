from __future__ import annotations

import re
from pathlib import Path

import structlog

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.inventory.value_objects import DiscoveredPlugin, DiscoveredTheme

logger = structlog.get_logger()

_PLUGIN_NAME_RE = re.compile(r"^[ \t*]*Plugin Name:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_PLUGIN_VER_RE = re.compile(r"^[ \t*]*Version:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_THEME_NAME_RE = re.compile(r"^[ \t*]*Theme Name:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_THEME_VER_RE = re.compile(r"^[ \t*]*Version:\s*(.+)$", re.MULTILINE | re.IGNORECASE)


class FilesystemWordPressExtensionScanner:
    """Reads installed plugins and themes from a WordPress installation's
    filesystem using only the PHP/CSS header conventions WordPress defines —
    no database access required.

    Plugins: inspects ``wp-content/plugins/{slug}/{slug}.php`` first
    (conventional), then falls back to scanning other ``.php`` files in the
    plugin root for a ``Plugin Name:`` header. Directories with no matching
    PHP file are silently skipped (not a valid plugin).

    Themes: reads ``wp-content/themes/{slug}/style.css`` for a ``Theme
    Name:`` header. Directories without ``style.css`` are silently skipped.

    Symlinks are never followed. OSErrors are logged and skipped so a
    single unreadable extension never aborts the scan for the entire
    installation.
    """

    async def scan_plugins(self, installation: WordPressInstallation) -> list[DiscoveredPlugin]:
        plugins_dir = Path(str(installation.absolute_path)) / "wp-content" / "plugins"
        if not plugins_dir.is_dir():
            logger.warning(
                "plugins_directory_missing",
                absolute_path=str(installation.absolute_path),
            )
            return []

        results: list[DiscoveredPlugin] = []
        try:
            entries = list(plugins_dir.iterdir())
        except OSError as exc:
            logger.warning("plugins_directory_unreadable", error=str(exc))
            return []

        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            plugin = self._read_plugin(entry, slug=entry.name)
            if plugin is not None:
                results.append(plugin)

        return results

    def _read_plugin(self, plugin_dir: Path, *, slug: str) -> DiscoveredPlugin | None:
        # Conventional main file is {slug}.php; scan it first, then others.
        conventional = plugin_dir / f"{slug}.php"
        candidates: list[Path] = []
        if conventional.exists():
            candidates.append(conventional)
        try:
            for f in plugin_dir.iterdir():
                if f.suffix == ".php" and f != conventional:
                    candidates.append(f)
        except OSError:
            pass

        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            try:
                content = candidate.read_text(errors="ignore")
            except OSError as exc:
                logger.warning("plugin_file_unreadable", path=str(candidate), error=str(exc))
                continue
            name_match = _PLUGIN_NAME_RE.search(content)
            if name_match:
                version_match = _PLUGIN_VER_RE.search(content)
                return DiscoveredPlugin(
                    slug=slug,
                    name=name_match.group(1).strip(),
                    version=version_match.group(1).strip() if version_match else None,
                )

        logger.debug("plugin_no_header_found", slug=slug, directory=str(plugin_dir))
        return None

    async def scan_themes(self, installation: WordPressInstallation) -> list[DiscoveredTheme]:
        themes_dir = Path(str(installation.absolute_path)) / "wp-content" / "themes"
        if not themes_dir.is_dir():
            logger.warning(
                "themes_directory_missing",
                absolute_path=str(installation.absolute_path),
            )
            return []

        results: list[DiscoveredTheme] = []
        try:
            entries = list(themes_dir.iterdir())
        except OSError as exc:
            logger.warning("themes_directory_unreadable", error=str(exc))
            return []

        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            style_css = entry / "style.css"
            if not style_css.is_file():
                continue
            try:
                content = style_css.read_text(errors="ignore")
            except OSError as exc:
                logger.warning("theme_style_unreadable", path=str(style_css), error=str(exc))
                continue
            name_match = _THEME_NAME_RE.search(content)
            if name_match is None:
                continue
            version_match = _THEME_VER_RE.search(content)
            results.append(
                DiscoveredTheme(
                    slug=entry.name,
                    name=name_match.group(1).strip(),
                    version=version_match.group(1).strip() if version_match else None,
                )
            )

        return results
