from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.domain.monitoring.value_objects import DiscoveredConfigItem
from sentinel.domain.shared.ports import Repository


class ConfigurationItemRepository(Repository[ConfigurationItem], Protocol):
    async def get_by_installation_source_and_key(
        self, installation_id: UUID, config_source: str, key: str
    ) -> ConfigurationItem | None: ...

    async def list_by_installation(self, installation_id: UUID) -> list[ConfigurationItem]: ...


class WordPressConfigurationScanner(Protocol):
    """Reads security-relevant configuration settings from a WordPress
    installation's filesystem.  Returns one ``DiscoveredConfigItem`` per
    tracked key (including keys expected-but-absent so the use case can
    reconcile them correctly)."""

    async def scan(self, installation: WordPressInstallation) -> list[DiscoveredConfigItem]: ...
