from __future__ import annotations

from typing import Protocol

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.shared.ports import Repository


class SecurityEventRepository(Repository[SecurityEvent], Protocol):
    async def list_unprocessed(self, *, limit: int = 200) -> list[SecurityEvent]: ...
