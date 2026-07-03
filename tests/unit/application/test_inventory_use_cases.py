from __future__ import annotations

from uuid import UUID, uuid4

from sentinel.application.inventory.use_cases import RunInventoryScanUseCase
from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.inventory.value_objects import DiscoveredPlugin, DiscoveredTheme
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName


class FakeWordPressInstallationRepository:
    def __init__(self, installations: list[WordPressInstallation]) -> None:
        self.by_id: dict[UUID, WordPressInstallation] = {i.id: i for i in installations}

    async def add(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> WordPressInstallation | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressInstallation]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None:
        return next((i for i in self.by_id.values() if str(i.absolute_path) == absolute_path), None)

    async def list_by_account(self, cpanel_account_id: UUID) -> list[WordPressInstallation]:
        return [i for i in self.by_id.values() if i.cpanel_account_id == cpanel_account_id]


class FakeInstalledPluginRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, InstalledPlugin] = {}

    async def add(self, entity: InstalledPlugin) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: InstalledPlugin) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> InstalledPlugin | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledPlugin]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledPlugin | None:
        return next(
            (
                p
                for p in self.by_id.values()
                if p.installation_id == installation_id and p.slug == slug
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledPlugin]:
        return [p for p in self.by_id.values() if p.installation_id == installation_id]


class FakeInstalledThemeRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, InstalledTheme] = {}

    async def add(self, entity: InstalledTheme) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: InstalledTheme) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> InstalledTheme | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledTheme]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledTheme | None:
        return next(
            (
                t
                for t in self.by_id.values()
                if t.installation_id == installation_id and t.slug == slug
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledTheme]:
        return [t for t in self.by_id.values() if t.installation_id == installation_id]


class FakeExtensionScanner:
    def __init__(
        self,
        plugins_by_id: dict[UUID, list[DiscoveredPlugin]] | None = None,
        themes_by_id: dict[UUID, list[DiscoveredTheme]] | None = None,
    ) -> None:
        self._plugins = plugins_by_id or {}
        self._themes = themes_by_id or {}

    async def scan_plugins(self, installation: WordPressInstallation) -> list[DiscoveredPlugin]:
        return self._plugins.get(installation.id, [])

    async def scan_themes(self, installation: WordPressInstallation) -> list[DiscoveredTheme]:
        return self._themes.get(installation.id, [])


def _installation(*, is_active: bool = True) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=uuid4(),
        absolute_path=AbsoluteFilePath(value="/home/examplebob/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.4.0",
        is_multisite=False,
        is_active=is_active,
        last_seen_at=utcnow(),
    )


def _dp(slug: str, name: str, version: str | None = "1.0.0") -> DiscoveredPlugin:
    return DiscoveredPlugin(slug=slug, name=name, version=version)


def _dt(slug: str, name: str, version: str | None = "1.0.0") -> DiscoveredTheme:
    return DiscoveredTheme(slug=slug, name=name, version=version)


def _use_case(
    installation: WordPressInstallation,
    plugins: FakeInstalledPluginRepository,
    themes: FakeInstalledThemeRepository,
    scanner: FakeExtensionScanner,
) -> RunInventoryScanUseCase:
    return RunInventoryScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        plugin_repository=plugins,
        theme_repository=themes,
        extension_scanner=scanner,
    )


async def test_first_scan_adds_all_plugins_and_themes() -> None:
    installation = _installation()
    plugins = FakeInstalledPluginRepository()
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(
        plugins_by_id={installation.id: [_dp("woocommerce", "WooCommerce")]},
        themes_by_id={installation.id: [_dt("twentytwentyfour", "Twenty Twenty-Four")]},
    )

    result = await _use_case(installation, plugins, themes, scanner).execute()

    assert result.installations_scanned == 1
    assert result.plugins_found == 1
    assert result.plugins_removed == 0
    assert result.themes_found == 1
    assert result.themes_removed == 0
    assert len(plugins.by_id) == 1
    assert len(themes.by_id) == 1


async def test_unchanged_plugin_is_marked_seen_not_duplicated() -> None:
    installation = _installation()
    existing_plugin = InstalledPlugin(
        installation_id=installation.id,
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=True,
        last_seen_at=utcnow(),
    )
    plugins = FakeInstalledPluginRepository()
    await plugins.add(existing_plugin)
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(
        plugins_by_id={installation.id: [_dp("woocommerce", "WooCommerce", "8.0.0")]},
    )

    result = await _use_case(installation, plugins, themes, scanner).execute()

    assert result.plugins_found == 1
    assert len(plugins.by_id) == 1  # no duplicate


async def test_version_change_updates_existing_plugin_row() -> None:
    installation = _installation()
    existing_plugin = InstalledPlugin(
        installation_id=installation.id,
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=True,
        last_seen_at=utcnow(),
    )
    plugins = FakeInstalledPluginRepository()
    await plugins.add(existing_plugin)
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(
        plugins_by_id={installation.id: [_dp("woocommerce", "WooCommerce", "8.1.0")]},
    )

    await _use_case(installation, plugins, themes, scanner).execute()

    (plugin,) = plugins.by_id.values()
    assert plugin.version == "8.1.0"


async def test_new_plugin_on_already_inventoried_installation_is_added() -> None:
    installation = _installation()
    existing_plugin = InstalledPlugin(
        installation_id=installation.id,
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=True,
        last_seen_at=utcnow(),
    )
    plugins = FakeInstalledPluginRepository()
    await plugins.add(existing_plugin)
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(
        plugins_by_id={
            installation.id: [
                _dp("woocommerce", "WooCommerce", "8.0.0"),
                _dp("jetpack", "Jetpack", "12.0"),
            ]
        },
    )

    result = await _use_case(installation, plugins, themes, scanner).execute()

    assert result.plugins_found == 2
    assert len(plugins.by_id) == 2


async def test_removed_plugin_is_marked_absent() -> None:
    installation = _installation()
    existing_plugin = InstalledPlugin(
        installation_id=installation.id,
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=True,
        last_seen_at=utcnow(),
    )
    plugins = FakeInstalledPluginRepository()
    await plugins.add(existing_plugin)
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(plugins_by_id={installation.id: []})

    result = await _use_case(installation, plugins, themes, scanner).execute()

    assert result.plugins_removed == 1
    (plugin,) = plugins.by_id.values()
    assert plugin.is_present is False


async def test_absent_plugin_that_reappears_is_marked_seen() -> None:
    installation = _installation()
    absent_plugin = InstalledPlugin(
        installation_id=installation.id,
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=False,
        last_seen_at=utcnow(),
    )
    plugins = FakeInstalledPluginRepository()
    await plugins.add(absent_plugin)
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(
        plugins_by_id={installation.id: [_dp("woocommerce", "WooCommerce", "8.1.0")]},
    )

    await _use_case(installation, plugins, themes, scanner).execute()

    assert len(plugins.by_id) == 1
    (plugin,) = plugins.by_id.values()
    assert plugin.is_present is True
    assert plugin.version == "8.1.0"


async def test_inactive_installation_is_skipped() -> None:
    installation = _installation(is_active=False)
    plugins = FakeInstalledPluginRepository()
    themes = FakeInstalledThemeRepository()
    scanner = FakeExtensionScanner(
        plugins_by_id={installation.id: [_dp("woocommerce", "WooCommerce")]},
    )

    result = await _use_case(installation, plugins, themes, scanner).execute()

    assert result.installations_scanned == 0
    assert len(plugins.by_id) == 0
