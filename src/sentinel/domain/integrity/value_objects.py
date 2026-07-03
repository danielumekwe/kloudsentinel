from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sentinel.domain.shared.entity import ValueObject
from sentinel.domain.shared.value_objects import RelativeFilePath, Sha256Hash


class ChangeType(StrEnum):
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    PERMISSIONS_CHANGED = "PERMISSIONS_CHANGED"


@dataclass(frozen=True, kw_only=True)
class ScannedFile(ValueObject):
    """Raw finding produced by a ``FileScanner`` adapter for one file under a
    cPanel account's home directory, before reconciliation against the
    account's persisted ``FileBaseline`` rows assigns it a change type."""

    relative_path: RelativeFilePath
    sha256: Sha256Hash
    size_bytes: int
    mode: str
