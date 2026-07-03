from __future__ import annotations

from uuid import uuid4

from sentinel.application.inventory.queries import (
    ListInstalledPluginsQuery,
    ListInstalledThemesQuery,
)
from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.shared.entity import utcnow
from tests.unit.application.test_inventory_use_cases import (
    FakeInstalledPluginRepository,
    FakeInstalledThemeRepository,
)


def _plugin() -> InstalledPlugin:
    return InstalledPlugin(
        installation_id=uuid4(),
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=True,
        last_seen_at=utcnow(),
    )


def _theme() -> InstalledTheme:
    return InstalledTheme(
        installation_id=uuid4(),
        slug="twentytwentyfour",
        name="Twenty Twenty-Four",
        version="1.0.0",
        is_present=True,
        last_seen_at=utcnow(),
    )


async def test_list_installed_plugins_query_delegates_to_repository() -> None:
    plugins = FakeInstalledPluginRepository()
    query = ListInstalledPluginsQuery(plugins)

    result = await query.execute(limit=50, offset=0)

    assert result == []


async def test_list_installed_plugins_query_returns_seeded_plugins() -> None:
    plugins = FakeInstalledPluginRepository()
    plugin = _plugin()
    await plugins.add(plugin)
    query = ListInstalledPluginsQuery(plugins)

    result = await query.execute(limit=50, offset=0)

    assert result == [plugin]


async def test_list_installed_themes_query_delegates_to_repository() -> None:
    themes = FakeInstalledThemeRepository()
    query = ListInstalledThemesQuery(themes)

    result = await query.execute(limit=50, offset=0)

    assert result == []


async def test_list_installed_themes_query_returns_seeded_themes() -> None:
    themes = FakeInstalledThemeRepository()
    theme = _theme()
    await themes.add(theme)
    query = ListInstalledThemesQuery(themes)

    result = await query.execute(limit=50, offset=0)

    assert result == [theme]
