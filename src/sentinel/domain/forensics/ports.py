from __future__ import annotations

from typing import Protocol

from sentinel.domain.forensics.entities import TempFileObservation
from sentinel.domain.shared.ports import Repository


class TempFileObservationRepository(Repository[TempFileObservation], Protocol):
    async def get_by_path(self, absolute_path: str) -> TempFileObservation | None: ...


class TempFileScanner(Protocol):
    """Scans the configured temp directories for new script-like files and
    classifies each one. May return files already seen on a prior scan —
    the use case is responsible for de-duplicating against persisted
    observations before raising any ``SecurityEvent``."""

    async def scan(self) -> list[TempFileObservation]: ...
