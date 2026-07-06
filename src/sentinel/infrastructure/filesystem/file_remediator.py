from __future__ import annotations

from pathlib import Path

import structlog

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.integrity.value_objects import QuarantinedFile
from sentinel.domain.shared.value_objects import RelativeFilePath
from sentinel.infrastructure.filesystem import _quarantine_ops

logger = structlog.get_logger()


class FilesystemFileRemediator:
    """Moves files between a cPanel account's home directory and a
    centralized quarantine store outside every account's home tree, so a
    quarantined file is never inside anything ``FilesystemFileScanner``
    walks or the web server can serve — it's only ever findable through
    Sentinel's own records.

    Each quarantined file lives at
    ``{quarantine_root}/{account.username}/{uuid4}_{basename}``: the random
    prefix avoids collisions between successive quarantines of files that
    share a basename.
    """

    def __init__(self, *, quarantine_root_directory: str) -> None:
        self._quarantine_root = Path(quarantine_root_directory)

    async def quarantine(
        self, *, account: CpanelAccount, relative_path: RelativeFilePath
    ) -> QuarantinedFile:
        home = Path(str(account.home_directory))
        source = _quarantine_ops.resolve_contained(
            home / str(relative_path),
            root=home,
            description=f"{relative_path} under {account.username}'s home directory",
        )
        account_dir = self._quarantine_root / str(account.username)

        quarantined = _quarantine_ops.quarantine_file(source, quarantine_dir=account_dir)
        logger.info(
            "file_quarantined", source=str(source), quarantine_path=quarantined.quarantine_path
        )
        return quarantined

    async def restore(
        self,
        *,
        account: CpanelAccount,
        relative_path: RelativeFilePath,
        quarantine_path: str,
        mode: str,
    ) -> None:
        home = Path(str(account.home_directory))
        destination = _quarantine_ops.resolve_contained(
            home / str(relative_path),
            root=home,
            description=f"{relative_path} under {account.username}'s home directory",
        )
        source = _quarantine_ops.resolve_contained(
            Path(quarantine_path), root=self._quarantine_root, description="quarantine path"
        )

        _quarantine_ops.restore_file(str(source), destination=destination, mode=mode)
        logger.info("file_restored", quarantine_path=str(source), destination=str(destination))

    async def purge(self, *, quarantine_path: str) -> None:
        path = _quarantine_ops.resolve_contained(
            Path(quarantine_path), root=self._quarantine_root, description="quarantine path"
        )
        _quarantine_ops.purge_file(str(path))
        logger.info("file_purged", quarantine_path=str(path))
