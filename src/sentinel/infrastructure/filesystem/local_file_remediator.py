from __future__ import annotations

from datetime import datetime
from pathlib import Path

import structlog

from sentinel.domain.integrity.value_objects import QuarantinedFile
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity
from sentinel.infrastructure.filesystem import _quarantine_ops

logger = structlog.get_logger()


class LocalFileRemediator:
    """Same quarantine/restore/purge mechanics as
    ``FilesystemFileRemediator``, but for an arbitrary local directory (e.g.
    an extracted WordPress backup on the user's own machine) with no cPanel
    account involved — used by the offline ``scan-archive`` CLI. Kept as a
    separate class rather than shoehorned behind the ``FileRemediator``
    Protocol, which is keyed on a ``CpanelAccount`` that doesn't exist here.
    """

    def __init__(self, *, root_directory: Path, quarantine_directory: Path) -> None:
        self._root = root_directory
        self._quarantine_root = quarantine_directory

    async def quarantine(
        self,
        *,
        relative_path: RelativeFilePath,
        detection_reason: str,
        severity: Severity,
        detected_at: datetime,
    ) -> QuarantinedFile:
        source = _quarantine_ops.resolve_contained(
            self._root / str(relative_path),
            root=self._root,
            description=f"{relative_path} under {self._root}",
        )

        quarantined = _quarantine_ops.quarantine_file(
            source,
            quarantine_dir=self._quarantine_root,
            detection_reason=detection_reason,
            severity=severity,
            detected_at=detected_at,
        )
        logger.info(
            "file_quarantined", source=str(source), quarantine_path=quarantined.quarantine_path
        )
        return quarantined

    async def restore(
        self,
        *,
        relative_path: RelativeFilePath,
        quarantine_path: str,
        mode: str,
        owner_uid: int | None = None,
        owner_gid: int | None = None,
    ) -> None:
        destination = _quarantine_ops.resolve_contained(
            self._root / str(relative_path),
            root=self._root,
            description=f"{relative_path} under {self._root}",
        )
        source = _quarantine_ops.resolve_contained(
            Path(quarantine_path), root=self._quarantine_root, description="quarantine path"
        )

        _quarantine_ops.restore_file(
            str(source),
            destination=destination,
            mode=mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        logger.info("file_restored", quarantine_path=str(source), destination=str(destination))

    async def purge(self, *, quarantine_path: str) -> None:
        path = _quarantine_ops.resolve_contained(
            Path(quarantine_path), root=self._quarantine_root, description="quarantine path"
        )
        _quarantine_ops.purge_folder(str(path))
        logger.info("file_purged", quarantine_path=str(path))
