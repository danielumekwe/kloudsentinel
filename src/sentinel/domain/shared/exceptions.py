from __future__ import annotations


class DomainError(Exception):
    """Base class for all errors raised by the domain layer."""


class ValidationError(DomainError):
    """A value object or entity was constructed with invalid data."""


class InvariantViolationError(DomainError):
    """An operation would leave an aggregate in an inconsistent state."""


class EntityNotFoundError(DomainError):
    def __init__(self, entity_name: str, entity_id: object) -> None:
        self.entity_name = entity_name
        self.entity_id = entity_id
        super().__init__(f"{entity_name} not found: {entity_id!r}")
