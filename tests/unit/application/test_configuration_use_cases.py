from __future__ import annotations

from uuid import UUID, uuid4

from sentinel.application.monitoring.use_cases import RunConfigurationScanUseCase
from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.domain.monitoring.value_objects import DiscoveredConfigItem
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName


class FakeWordPressInstallationRepository:
    def __init__(self, installations: list[WordPressInstallation]) -> None:
        self.by_id: dict[UUID, WordPressInstallation] = {i.id: i for i in installations}

    async def add(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> WordPressInstallation | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressInstallation]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None:
        return next((i for i in self.by_id.values() if str(i.absolute_path) == absolute_path), None)

    async def list_by_account(self, cpanel_account_id: UUID) -> list[WordPressInstallation]:
        return [i for i in self.by_id.values() if i.cpanel_account_id == cpanel_account_id]


class FakeConfigurationItemRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, ConfigurationItem] = {}

    async def add(self, entity: ConfigurationItem) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: ConfigurationItem) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> ConfigurationItem | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[ConfigurationItem]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_source_and_key(
        self, installation_id: UUID, config_source: str, key: str
    ) -> ConfigurationItem | None:
        return next(
            (
                i
                for i in self.by_id.values()
                if i.installation_id == installation_id
                and i.config_source == config_source
                and i.key == key
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[ConfigurationItem]:
        return [i for i in self.by_id.values() if i.installation_id == installation_id]


class FakeConfigurationScanner:
    def __init__(self, items_by_id: dict[UUID, list[DiscoveredConfigItem]] | None = None) -> None:
        self._items = items_by_id or {}

    async def scan(self, installation: WordPressInstallation) -> list[DiscoveredConfigItem]:
        return self._items.get(installation.id, [])


def _installation(*, is_active: bool = True) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=uuid4(),
        absolute_path=AbsoluteFilePath(value="/home/bob/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.4.0",
        is_multisite=False,
        is_active=is_active,
        last_seen_at=utcnow(),
    )


def _dci(
    key: str,
    raw_value: str | None = "false",
    *,
    is_flagged: bool = False,
    flag_reason: str | None = None,
    config_source: str = "wp-config.php",
) -> DiscoveredConfigItem:
    return DiscoveredConfigItem(
        config_source=config_source,
        key=key,
        raw_value=raw_value,
        is_flagged=is_flagged,
        flag_reason=flag_reason,
    )


def _use_case(
    installation: WordPressInstallation,
    items: FakeConfigurationItemRepository,
    scanner: FakeConfigurationScanner,
) -> RunConfigurationScanUseCase:
    return RunConfigurationScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        item_repository=items,
        config_scanner=scanner,
    )


async def test_first_scan_adds_all_discovered_items() -> None:
    installation = _installation()
    items = FakeConfigurationItemRepository()
    scanner = FakeConfigurationScanner(
        items_by_id={
            installation.id: [
                _dci("WP_DEBUG", "false"),
                _dci("DISALLOW_FILE_EDIT", "true"),
            ]
        }
    )

    result = await _use_case(installation, items, scanner).execute()

    assert result.installations_scanned == 1
    assert result.items_found == 2
    assert result.items_removed == 0
    assert len(items.by_id) == 2


async def test_flagged_items_counted_correctly() -> None:
    installation = _installation()
    items = FakeConfigurationItemRepository()
    scanner = FakeConfigurationScanner(
        items_by_id={
            installation.id: [
                _dci("WP_DEBUG", "true", is_flagged=True, flag_reason="Debug mode is enabled"),
                _dci("DISALLOW_FILE_EDIT", "true"),
            ]
        }
    )

    result = await _use_case(installation, items, scanner).execute()

    assert result.items_flagged == 1


async def test_value_change_updates_existing_item() -> None:
    installation = _installation()
    existing = ConfigurationItem(
        installation_id=installation.id,
        config_source="wp-config.php",
        key="WP_DEBUG",
        raw_value="false",
        is_flagged=False,
        flag_reason=None,
        is_present=True,
        last_seen_at=utcnow(),
    )
    items = FakeConfigurationItemRepository()
    await items.add(existing)
    scanner = FakeConfigurationScanner(
        items_by_id={
            installation.id: [
                _dci("WP_DEBUG", "true", is_flagged=True, flag_reason="Debug mode is enabled"),
            ]
        }
    )

    await _use_case(installation, items, scanner).execute()

    (item,) = items.by_id.values()
    assert item.raw_value == "true"
    assert item.is_flagged is True
    assert len(items.by_id) == 1  # no duplicate


async def test_absent_item_gets_marked_absent() -> None:
    installation = _installation()
    existing = ConfigurationItem(
        installation_id=installation.id,
        config_source="wp-config.php",
        key="WP_DEBUG",
        raw_value="false",
        is_flagged=False,
        flag_reason=None,
        is_present=True,
        last_seen_at=utcnow(),
    )
    items = FakeConfigurationItemRepository()
    await items.add(existing)
    scanner = FakeConfigurationScanner(items_by_id={installation.id: []})

    result = await _use_case(installation, items, scanner).execute()

    assert result.items_removed == 1
    (item,) = items.by_id.values()
    assert item.is_present is False


async def test_absent_item_that_reappears_is_marked_seen() -> None:
    installation = _installation()
    existing = ConfigurationItem(
        installation_id=installation.id,
        config_source="wp-config.php",
        key="WP_DEBUG",
        raw_value="false",
        is_flagged=False,
        flag_reason=None,
        is_present=False,
        last_seen_at=utcnow(),
    )
    items = FakeConfigurationItemRepository()
    await items.add(existing)
    scanner = FakeConfigurationScanner(
        items_by_id={installation.id: [_dci("WP_DEBUG", "true", is_flagged=True, flag_reason="r")]}
    )

    await _use_case(installation, items, scanner).execute()

    assert len(items.by_id) == 1
    (item,) = items.by_id.values()
    assert item.is_present is True
    assert item.raw_value == "true"


async def test_inactive_installation_is_skipped() -> None:
    installation = _installation(is_active=False)
    items = FakeConfigurationItemRepository()
    scanner = FakeConfigurationScanner(items_by_id={installation.id: [_dci("WP_DEBUG", "false")]})

    result = await _use_case(installation, items, scanner).execute()

    assert result.installations_scanned == 0
    assert len(items.by_id) == 0
