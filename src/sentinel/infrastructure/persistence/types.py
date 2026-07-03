from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.engine import Dialect
from sqlalchemy.types import CHAR, TypeDecorator


class GUID(TypeDecorator[uuid.UUID]):
    """Stores a Python ``uuid.UUID`` as a 36-character hyphenated string.

    SQLAlchemy's built-in ``Uuid`` type falls back to a 32-character hex blob
    (no hyphens) on backends without native UUID support, which would silently
    diverge from the ``CHAR(36)`` column format specified in the database
    design doc. This type decorator guarantees the on-disk format regardless
    of dialect, so the schema is identical whether the engine is SQLite today
    or PostgreSQL in a future migration.
    """

    impl = CHAR(36)
    cache_ok = True

    def process_bind_param(self, value: uuid.UUID | str | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return str(value)
        return str(uuid.UUID(value))

    def process_result_value(self, value: Any, dialect: Dialect) -> uuid.UUID | None:
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(value)
