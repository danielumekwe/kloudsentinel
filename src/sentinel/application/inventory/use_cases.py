from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.inventory.ports import (
    InstalledPluginRepository,
    InstalledThemeRepository,
    WordPressExtensionScanner,
)
from sentinel.domain.inventory.value_objects import DiscoveredPlugin, DiscoveredTheme
from sentinel.domain.shared.entity import utcnow

logger = structlog.get_logger()


@dataclass(frozen=True)
class InventoryScanResult:
    installations_scanned: int
    plugins_found: int
    plugins_removed: int
    themes_found: int
    themes_removed: int


class RunInventoryScanUseCase:
    """Reconciles installed WordPress plugins and themes against persisted
    state for every active ``WordPressInstallation``.

    Pure state-tracking — no security findings are raised here. Extensions
    are marked absent when they disappear from the filesystem; version
    changes and reappearances are captured in-place so the row count
    stays stable over time.
    """

    def __init__(
        self,
        *,
        installation_repository: WordPressInstallationRepository,
        plugin_repository: InstalledPluginRepository,
        theme_repository: InstalledThemeRepository,
        extension_scanner: WordPressExtensionScanner,
    ) -> None:
        self._installations = installation_repository
        self._plugins = plugin_repository
        self._themes = theme_repository
        self._scanner = extension_scanner

    async def execute(self) -> InventoryScanResult:
        now = utcnow()
        all_installations = await self._installations.list(limit=10_000)
        active = [i for i in all_installations if i.is_active]

        total_plugins_found = total_plugins_removed = 0
        total_themes_found = total_themes_removed = 0

        for installation in active:
            pf, pr, tf, tr = await self._scan_installation(installation, at=now)
            total_plugins_found += pf
            total_plugins_removed += pr
            total_themes_found += tf
            total_themes_removed += tr

        logger.info(
            "inventory_scan_completed",
            installations_scanned=len(active),
            plugins_found=total_plugins_found,
            plugins_removed=total_plugins_removed,
            themes_found=total_themes_found,
            themes_removed=total_themes_removed,
        )

        return InventoryScanResult(
            installations_scanned=len(active),
            plugins_found=total_plugins_found,
            plugins_removed=total_plugins_removed,
            themes_found=total_themes_found,
            themes_removed=total_themes_removed,
        )

    async def _scan_installation(
        self, installation: WordPressInstallation, *, at: datetime
    ) -> tuple[int, int, int, int]:
        existing_plugins = await self._plugins.list_by_installation(installation.id)
        existing_themes = await self._themes.list_by_installation(installation.id)

        discovered_plugins = await self._scanner.scan_plugins(installation)
        discovered_themes = await self._scanner.scan_themes(installation)

        plugins_found, plugins_removed = await self._reconcile_plugins(
            installation.id, existing_plugins, discovered_plugins, at=at
        )
        themes_found, themes_removed = await self._reconcile_themes(
            installation.id, existing_themes, discovered_themes, at=at
        )

        return plugins_found, plugins_removed, themes_found, themes_removed

    async def _reconcile_plugins(
        self,
        installation_id: UUID,
        existing: list[InstalledPlugin],
        discovered: list[DiscoveredPlugin],
        *,
        at: datetime,
    ) -> tuple[int, int]:
        existing_by_slug = {p.slug: p for p in existing}
        seen_slugs: set[str] = set()
        found = 0

        for item in discovered:
            seen_slugs.add(item.slug)
            existing_plugin = existing_by_slug.get(item.slug)
            if existing_plugin is None:
                plugin = InstalledPlugin(
                    installation_id=installation_id,
                    slug=item.slug,
                    name=item.name,
                    version=item.version,
                    last_seen_at=at,
                )
                await self._plugins.add(plugin)
            else:
                existing_plugin.mark_seen(name=item.name, version=item.version, at=at)
                await self._plugins.save(existing_plugin)
            found += 1

        removed = 0
        for slug, plugin in existing_by_slug.items():
            if plugin.is_present and slug not in seen_slugs:
                plugin.mark_absent(at=at)
                await self._plugins.save(plugin)
                removed += 1

        return found, removed

    async def _reconcile_themes(
        self,
        installation_id: UUID,
        existing: list[InstalledTheme],
        discovered: list[DiscoveredTheme],
        *,
        at: datetime,
    ) -> tuple[int, int]:
        existing_by_slug = {t.slug: t for t in existing}
        seen_slugs: set[str] = set()
        found = 0

        for item in discovered:
            seen_slugs.add(item.slug)
            existing_theme = existing_by_slug.get(item.slug)
            if existing_theme is None:
                theme = InstalledTheme(
                    installation_id=installation_id,
                    slug=item.slug,
                    name=item.name,
                    version=item.version,
                    last_seen_at=at,
                )
                await self._themes.add(theme)
            else:
                existing_theme.mark_seen(name=item.name, version=item.version, at=at)
                await self._themes.save(existing_theme)
            found += 1

        removed = 0
        for slug, theme in existing_by_slug.items():
            if theme.is_present and slug not in seen_slugs:
                theme.mark_absent(at=at)
                await self._themes.save(theme)
                removed += 1

        return found, removed
