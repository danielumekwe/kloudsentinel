from __future__ import annotations

from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.inventory.ports import InstalledPluginRepository, InstalledThemeRepository


class ListInstalledPluginsQuery:
    def __init__(self, plugin_repository: InstalledPluginRepository) -> None:
        self._plugins = plugin_repository

    async def execute(self, *, limit: int, offset: int) -> list[InstalledPlugin]:
        return await self._plugins.list(limit=limit, offset=offset)


class ListInstalledThemesQuery:
    def __init__(self, theme_repository: InstalledThemeRepository) -> None:
        self._themes = theme_repository

    async def execute(self, *, limit: int, offset: int) -> list[InstalledTheme]:
        return await self._themes.list(limit=limit, offset=offset)
