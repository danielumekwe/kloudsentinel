from __future__ import annotations

import hashlib
from pathlib import Path

import structlog

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.integrity.value_objects import ScannedFile
from sentinel.domain.shared.value_objects import RelativeFilePath, Sha256Hash

logger = structlog.get_logger()

_HASH_CHUNK_SIZE = 65536


class FilesystemFileScanner:
    """Walks a cPanel account's home directory and hashes every file found,
    for ``RunIntegrityScanUseCase`` to diff against persisted baselines.

    Skips symlinked directories for the same reason as
    ``FilesystemWordPressDetector``: home directories can contain symlinks
    back into shared or unrelated trees, and following them would make scan
    scope unbounded. A path is excluded if it contains any of
    ``excluded_relative_paths`` as a substring, so one entry (e.g.
    ``wp-content/uploads``) excludes that subtree regardless of which
    directory inside the account it lives under. Files over
    ``max_file_size_bytes`` (mail spools, backups) are skipped rather than
    hashed, so one pathological file can't dominate a scan's runtime.
    """

    def __init__(self, *, excluded_relative_paths: list[str], max_file_size_bytes: int) -> None:
        self._excluded_relative_paths = excluded_relative_paths
        self._max_file_size_bytes = max_file_size_bytes

    async def scan(self, account: CpanelAccount) -> list[ScannedFile]:
        home = Path(str(account.home_directory))
        if not home.is_dir():
            logger.warning("account_home_missing", home_directory=str(home))
            return []

        findings: list[ScannedFile] = []
        for file_path in self._walk(home):
            relative = file_path.relative_to(home).as_posix()
            if self._is_excluded(relative):
                continue

            scanned = self._scan_file(file_path, relative)
            if scanned is not None:
                findings.append(scanned)

        return findings

    def _walk(self, directory: Path) -> list[Path]:
        try:
            entries = list(directory.iterdir())
        except (PermissionError, OSError):
            return []

        files: list[Path] = []
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                files.extend(self._walk(entry))
            elif entry.is_file():
                files.append(entry)
        return files

    def _is_excluded(self, relative_path: str) -> bool:
        return any(marker in relative_path for marker in self._excluded_relative_paths)

    def _scan_file(self, file_path: Path, relative_path: str) -> ScannedFile | None:
        try:
            stat = file_path.stat()
        except OSError:
            logger.warning("file_stat_failed", path=str(file_path))
            return None

        if stat.st_size > self._max_file_size_bytes:
            logger.info("file_skipped_too_large", path=str(file_path), size_bytes=stat.st_size)
            return None

        digest = hashlib.sha256()
        try:
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
                    digest.update(chunk)
        except OSError:
            logger.warning("file_read_failed", path=str(file_path))
            return None

        return ScannedFile(
            relative_path=RelativeFilePath(value=relative_path),
            sha256=Sha256Hash(value=digest.hexdigest()),
            size_bytes=stat.st_size,
            mode=format(stat.st_mode & 0o777, "03o"),
        )
