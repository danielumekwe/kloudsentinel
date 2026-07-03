from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.domain.monitoring.ports import (
    ConfigurationItemRepository,
    WordPressConfigurationScanner,
)
from sentinel.domain.monitoring.value_objects import DiscoveredConfigItem
from sentinel.domain.shared.entity import utcnow

logger = structlog.get_logger()


@dataclass(frozen=True)
class ConfigurationScanResult:
    installations_scanned: int
    items_found: int
    items_flagged: int
    items_removed: int


class RunConfigurationScanUseCase:
    """Reconciles security-relevant configuration settings for every active
    ``WordPressInstallation`` against persisted state.

    Pure state-tracking — no security findings are raised here.  Items are
    marked absent when they disappear; value or flag changes are updated
    in-place so the row count stays stable over time.
    """

    def __init__(
        self,
        *,
        installation_repository: WordPressInstallationRepository,
        item_repository: ConfigurationItemRepository,
        config_scanner: WordPressConfigurationScanner,
    ) -> None:
        self._installations = installation_repository
        self._items = item_repository
        self._scanner = config_scanner

    async def execute(self) -> ConfigurationScanResult:
        now = utcnow()
        all_installations = await self._installations.list(limit=10_000)
        active = [i for i in all_installations if i.is_active]

        total_found = total_flagged = total_removed = 0

        for installation in active:
            found, flagged, removed = await self._scan_installation(installation, at=now)
            total_found += found
            total_flagged += flagged
            total_removed += removed

        logger.info(
            "configuration_scan_completed",
            installations_scanned=len(active),
            items_found=total_found,
            items_flagged=total_flagged,
            items_removed=total_removed,
        )

        return ConfigurationScanResult(
            installations_scanned=len(active),
            items_found=total_found,
            items_flagged=total_flagged,
            items_removed=total_removed,
        )

    async def _scan_installation(
        self, installation: WordPressInstallation, *, at: datetime
    ) -> tuple[int, int, int]:
        existing = await self._items.list_by_installation(installation.id)
        discovered = await self._scanner.scan(installation)
        return await self._reconcile(installation.id, existing, discovered, at=at)

    async def _reconcile(
        self,
        installation_id: UUID,
        existing: list[ConfigurationItem],
        discovered: list[DiscoveredConfigItem],
        *,
        at: datetime,
    ) -> tuple[int, int, int]:
        # Key is (config_source, key) — unique per installation
        existing_by_source_key = {(i.config_source, i.key): i for i in existing}
        seen: set[tuple[str, str]] = set()
        found = flagged = 0

        for item in discovered:
            source_key = (item.config_source, item.key)
            seen.add(source_key)
            existing_item = existing_by_source_key.get(source_key)
            if existing_item is None:
                config_item = ConfigurationItem(
                    installation_id=installation_id,
                    config_source=item.config_source,
                    key=item.key,
                    raw_value=item.raw_value,
                    is_flagged=item.is_flagged,
                    flag_reason=item.flag_reason,
                    last_seen_at=at,
                )
                await self._items.add(config_item)
            else:
                existing_item.mark_seen(
                    raw_value=item.raw_value,
                    is_flagged=item.is_flagged,
                    flag_reason=item.flag_reason,
                    at=at,
                )
                await self._items.save(existing_item)
            found += 1
            if item.is_flagged:
                flagged += 1

        removed = 0
        for source_key, existing_item in existing_by_source_key.items():
            if existing_item.is_present and source_key not in seen:
                existing_item.mark_absent(at=at)
                await self._items.save(existing_item)
                removed += 1

        return found, flagged, removed
