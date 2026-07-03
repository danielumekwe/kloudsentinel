from __future__ import annotations

from sentinel.domain.discovery.entities import CpanelAccount, WordPressInstallation
from sentinel.domain.discovery.ports import CpanelAccountRepository, WordPressInstallationRepository


class ListCpanelAccountsQuery:
    """Thin application-layer read query. Exists so the API layer depends only
    on the application layer (never directly on a repository implementation),
    keeping the dependency direction consistent even for trivial reads."""

    def __init__(self, account_repository: CpanelAccountRepository) -> None:
        self._accounts = account_repository

    async def execute(self, *, limit: int, offset: int) -> list[CpanelAccount]:
        return await self._accounts.list(limit=limit, offset=offset)


class ListWordPressInstallationsQuery:
    def __init__(self, installation_repository: WordPressInstallationRepository) -> None:
        self._installations = installation_repository

    async def execute(self, *, limit: int, offset: int) -> list[WordPressInstallation]:
        return await self._installations.list(limit=limit, offset=offset)
