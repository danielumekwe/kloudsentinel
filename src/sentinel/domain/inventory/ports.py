from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.inventory.value_objects import DiscoveredPlugin, DiscoveredTheme
from sentinel.domain.shared.ports import Repository


class InstalledPluginRepository(Repository[InstalledPlugin], Protocol):
    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledPlugin | None: ...

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledPlugin]: ...


class InstalledThemeRepository(Repository[InstalledTheme], Protocol):
    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledTheme | None: ...

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledTheme]: ...


class WordPressExtensionScanner(Protocol):
    """Reads installed plugins and themes from a WordPress installation's
    filesystem. Decoupled from ``FilesystemWordPressExtensionScanner`` so the
    inventory use case stays testable without touching the real filesystem."""

    async def scan_plugins(self, installation: WordPressInstallation) -> list[DiscoveredPlugin]: ...

    async def scan_themes(self, installation: WordPressInstallation) -> list[DiscoveredTheme]: ...
