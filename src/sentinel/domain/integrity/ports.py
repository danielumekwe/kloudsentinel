from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding, RemediationAction
from sentinel.domain.integrity.value_objects import QuarantinedFile, ScannedFile
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


class RemediationActionRepository(Repository[RemediationAction], Protocol):
    async def list_by_finding(self, finding_id: UUID) -> list[RemediationAction]: ...


class FileScanner(Protocol):
    """Scans a cPanel account's home directory and returns the current state
    of every file found, for the use case to diff against persisted
    baselines."""

    async def scan(self, account: CpanelAccount) -> list[ScannedFile]: ...


class FileRemediator(Protocol):
    """Performs the on-disk side of remediating an ``IntegrityFinding``:
    moving a suspicious file out of place, putting a quarantined file back,
    or permanently erasing a quarantined copy. Raises
    ``FileRemediationError`` on any filesystem failure."""

    async def quarantine(
        self, *, account: CpanelAccount, relative_path: RelativeFilePath
    ) -> QuarantinedFile: ...

    async def restore(
        self,
        *,
        account: CpanelAccount,
        relative_path: RelativeFilePath,
        quarantine_path: str,
        mode: str,
    ) -> None: ...

    async def purge(self, *, quarantine_path: str) -> None: ...
