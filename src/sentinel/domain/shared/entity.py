from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Reattaches UTC tzinfo to a naive datetime.

    Every datetime in this codebase originates from ``utcnow()`` (always
    timezone-aware), but SQLite's plain ``DateTime`` column type strips
    tzinfo on round-trip — the wall-clock value read back is still UTC, it's
    just naive. That's harmless as long as datetimes are only ever assigned
    or displayed, but comparing one freshly created (aware) against one read
    back from the database (naive) raises ``TypeError``. Repositories that
    need to compare timestamps (e.g. the intelligence context's correlation
    window) should pass every datetime field through this on the way out of
    the database.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


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
