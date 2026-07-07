from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.shared.ports import Repository


class SecurityEventRepository(Repository[SecurityEvent], Protocol):
    async def list_unprocessed(self, *, limit: int = 200) -> list[SecurityEvent]: ...

    async def count_total(self) -> int: ...

    async def count_unprocessed(self) -> int: ...

    async def list_by_account(
        self, account_id: UUID, *, limit: int = 200
    ) -> list[SecurityEvent]: ...
