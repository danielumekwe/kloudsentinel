from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding
from sentinel.domain.integrity.value_objects import ScannedFile
from sentinel.domain.shared.ports import Repository
from sentinel.domain.shared.value_objects import RelativeFilePath


class FileBaselineRepository(Repository[FileBaseline], Protocol):
    async def get_by_account_and_path(
        self, account_id: UUID, relative_path: RelativeFilePath
    ) -> FileBaseline | None: ...

    async def list_by_account(self, account_id: UUID) -> list[FileBaseline]: ...


class IntegrityFindingRepository(Repository[IntegrityFinding], Protocol):
    async def list_unacknowledged(
        self, *, limit: int = 50, offset: int = 0
    ) -> list[IntegrityFinding]: ...


class FileScanner(Protocol):
    """Scans a cPanel account's home directory and returns the current state
    of every file found, for the use case to diff against persisted
    baselines."""

    async def scan(self, account: CpanelAccount) -> list[ScannedFile]: ...
