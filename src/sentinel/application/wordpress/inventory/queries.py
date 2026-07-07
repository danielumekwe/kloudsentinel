from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.integrity.ports import FileBaselineRepository
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import AbsoluteFilePath, RelativeFilePath


@dataclass(frozen=True)
class DropInStatus:
    relative_path: str
    is_present: bool
    sha256: str | None


@dataclass(frozen=True)
class WordPressInventoryReport:
    installation_id: UUID
    wp_version: str | None
    php_version: str | None
    drop_ins: list[DropInStatus]
    must_use_plugins: list[str]


class GetWordPressInventoryQuery:
    """Surfaces drop-in and must-use-plugin presence without any new
    storage: drop-ins (``wp-content/db.php`` etc.) are already recorded by
    the generic file-integrity baseline every account already has —
    ``FileBaselineRepository.get_by_account_and_path`` — reused verbatim.
    Must-use plugins have no baseline-independent identity worth
    persisting, so they're a live, read-only directory listing instead.
    """

    def __init__(
        self,
        *,
        installation_repository: WordPressInstallationRepository,
        baseline_repository: FileBaselineRepository,
        dropin_relative_paths: list[str],
    ) -> None:
        self._installations = installation_repository
        self._baselines = baseline_repository
        self._dropin_paths = dropin_relative_paths

    async def execute(self, installation_id: UUID) -> WordPressInventoryReport:
        installation = await self._installations.get(installation_id)
        if installation is None:
            raise EntityNotFoundError("WordPressInstallation", installation_id)

        drop_ins: list[DropInStatus] = []
        for path in self._dropin_paths:
            baseline = await self._baselines.get_by_account_and_path(
                installation.cpanel_account_id, RelativeFilePath(value=path)
            )
            present = baseline is not None and baseline.is_active
            drop_ins.append(
                DropInStatus(
                    relative_path=path,
                    is_present=present,
                    sha256=str(baseline.sha256) if present and baseline is not None else None,
                )
            )

        return WordPressInventoryReport(
            installation_id=installation.id,
            wp_version=installation.wp_version,
            php_version=installation.php_version,
            drop_ins=drop_ins,
            must_use_plugins=self._list_mu_plugins(installation.absolute_path),
        )

    def _list_mu_plugins(self, absolute_path: AbsoluteFilePath) -> list[str]:
        mu_plugins_dir = Path(str(absolute_path)) / "wp-content" / "mu-plugins"
        try:
            return sorted(
                entry.name
                for entry in mu_plugins_dir.iterdir()
                if entry.is_file() and entry.suffix == ".php"
            )
        except OSError:
            return []
