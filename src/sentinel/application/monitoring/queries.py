from __future__ import annotations

from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.domain.monitoring.ports import ConfigurationItemRepository


class ListConfigurationItemsQuery:
    def __init__(self, repository: ConfigurationItemRepository) -> None:
        self._repository = repository

    async def execute(self, *, limit: int = 50, offset: int = 0) -> list[ConfigurationItem]:
        return await self._repository.list(limit=limit, offset=offset)
