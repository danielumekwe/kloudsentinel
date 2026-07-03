from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(kw_only=True)
class BaseEntity:
    """Identity-based equality. Two entities are equal iff same type and same id,
    regardless of attribute values — this is what distinguishes an Entity from a
    Value Object in DDD."""

    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash((type(self), self.id))

    def touch(self) -> None:
        self.updated_at = utcnow()


@dataclass(frozen=True, kw_only=True)
class ValueObject:
    """Marker base for value objects: equality and hashing are structural
    (field-by-field), provided automatically by frozen dataclass semantics.
    Value objects must never carry an id or mutable state."""
