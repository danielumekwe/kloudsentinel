from __future__ import annotations

from typing import Protocol, TypeVar
from uuid import UUID

from sentinel.domain.shared.entity import BaseEntity

TEntity = TypeVar("TEntity", bound=BaseEntity)


class Repository(Protocol[TEntity]):
    """Structural interface every domain-specific repository port conforms to.

    Concrete bounded contexts (discovery, integrity, inventory, ...) define their
    own narrow port interfaces in their own ``ports.py``. Most will extend this
    rather than use it directly, since real query needs are rarely plain CRUD —
    but every one of them needs at least this much.
    """

    async def add(self, entity: TEntity) -> None: ...

    async def save(self, entity: TEntity) -> None:
        """Persists in-place mutations made to an entity previously returned
        by ``get``/``list``. Domain entities are plain dataclasses, not
        session-tracked ORM objects, so mutating one's fields has no effect
        until the repository is explicitly told to write it back."""
        ...

    async def get(self, entity_id: UUID) -> TEntity | None: ...

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[TEntity]: ...
