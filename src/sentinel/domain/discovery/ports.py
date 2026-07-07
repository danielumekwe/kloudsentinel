from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.discovery.entities import CpanelAccount, Server, WordPressInstallation
from sentinel.domain.discovery.value_objects import (
    DiscoveredCpanelAccount,
    DiscoveredWordPressInstallation,
    LinuxUsername,
)
from sentinel.domain.shared.ports import Repository


class ServerRepository(Repository[Server], Protocol):
    async def get_by_hostname(self, hostname: str) -> Server | None: ...


class CpanelAccountRepository(Repository[CpanelAccount], Protocol):
    async def get_by_username(self, username: LinuxUsername) -> CpanelAccount | None: ...

    async def list_by_server(self, server_id: UUID) -> list[CpanelAccount]: ...

    async def count_total(self) -> int: ...


class WordPressInstallationRepository(Repository[WordPressInstallation], Protocol):
    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None: ...

    async def list_by_account(self, cpanel_account_id: UUID) -> list[WordPressInstallation]: ...


class HostInfoProvider(Protocol):
    """Reads identifying information about the host machine. Kept as a port
    so the discovery use case never calls ``socket``/``platform`` directly —
    it stays testable without touching the real machine."""

    def get_hostname(self) -> str: ...

    def get_os_info(self) -> str: ...

    def get_agent_version(self) -> str: ...


class CpanelAccountReader(Protocol):
    """Reads the set of cPanel accounts currently present on this host."""

    async def discover(self) -> list[DiscoveredCpanelAccount]: ...


class WordPressDetector(Protocol):
    """Scans a cPanel account's home directory for WordPress installations."""

    async def detect(self, account: CpanelAccount) -> list[DiscoveredWordPressInstallation]: ...
