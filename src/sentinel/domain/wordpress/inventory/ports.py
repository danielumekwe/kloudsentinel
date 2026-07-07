from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.shared.ports import Repository
from sentinel.domain.wordpress.inventory.entities import WordPressCronJob


class WordPressCronJobRepository(Repository[WordPressCronJob], Protocol):
    async def list_by_installation(self, installation_id: UUID) -> list[WordPressCronJob]: ...

    async def get_by_installation_and_command(
        self, installation_id: UUID, command: str
    ) -> WordPressCronJob | None: ...
