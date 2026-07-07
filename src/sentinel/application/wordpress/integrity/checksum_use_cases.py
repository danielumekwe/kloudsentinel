from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.integrity.ports import FileBaselineRepository
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import RelativeFilePath
from sentinel.domain.wordpress.integrity.entities import CoreChecksumRecord
from sentinel.domain.wordpress.integrity.ports import (
    CoreChecksumRepository,
    WordPressChecksumsClient,
)

CoreFileStatus = Literal["MATCH", "MISMATCH", "UNKNOWN", "NOT_TRACKED"]


@dataclass(frozen=True)
class CoreFileVerification:
    relative_path: str
    status: CoreFileStatus
    expected_sha256: str | None
    actual_sha256: str | None


class VerifyCoreChecksumsUseCase:
    """Compares an installation's critical files against WordPress.org's
    official per-release checksums — a stronger, independent signal than
    baseline hash-diffing alone, which only proves a file changed from
    whatever Sentinel last saw (an attacker who tampers with a file before
    the first baseline scan would poison the baseline itself).

    Site-specific files (``wp-config.php``) and drop-ins
    (``wp-content/db.php`` etc.) are never part of WordPress's official
    release and always report ``NOT_TRACKED`` — that's expected, not a bug.
    """

    def __init__(
        self,
        *,
        installation_repository: WordPressInstallationRepository,
        baseline_repository: FileBaselineRepository,
        checksum_repository: CoreChecksumRepository,
        checksums_client: WordPressChecksumsClient,
        critical_relative_paths: list[str],
    ) -> None:
        self._installations = installation_repository
        self._baselines = baseline_repository
        self._checksums = checksum_repository
        self._checksums_client = checksums_client
        self._critical_paths = critical_relative_paths

    async def execute(self, installation_id: UUID) -> list[CoreFileVerification]:
        installation = await self._installations.get(installation_id)
        if installation is None:
            raise EntityNotFoundError("WordPressInstallation", installation_id)

        if installation.wp_version is None:
            return [
                CoreFileVerification(
                    relative_path=path, status="UNKNOWN", expected_sha256=None, actual_sha256=None
                )
                for path in self._critical_paths
            ]

        await self._ensure_checksums_cached(installation.wp_version)

        results: list[CoreFileVerification] = []
        for path in self._critical_paths:
            record = await self._checksums.get_by_version_and_path(installation.wp_version, path)
            baseline = await self._baselines.get_by_account_and_path(
                installation.cpanel_account_id, RelativeFilePath(value=path)
            )
            actual = str(baseline.sha256) if baseline is not None and baseline.is_active else None

            if record is None:
                status: CoreFileStatus = "NOT_TRACKED"
            elif actual is None:
                status = "UNKNOWN"
            elif actual == record.sha256:
                status = "MATCH"
            else:
                status = "MISMATCH"

            results.append(
                CoreFileVerification(
                    relative_path=path,
                    status=status,
                    expected_sha256=record.sha256 if record is not None else None,
                    actual_sha256=actual,
                )
            )
        return results

    async def _ensure_checksums_cached(self, wp_version: str) -> None:
        if await self._checksums.has_version(wp_version):
            return
        fetched = await self._checksums_client.fetch_checksums(wp_version)
        now = utcnow()
        for relative_path, sha256 in fetched.items():
            await self._checksums.add(
                CoreChecksumRecord(
                    wp_version=wp_version,
                    relative_path=relative_path,
                    sha256=sha256,
                    fetched_at=now,
                )
            )
