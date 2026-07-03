from __future__ import annotations

from uuid import uuid4

from sentinel.application.monitoring.queries import ListConfigurationItemsQuery
from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.domain.shared.entity import utcnow
from tests.unit.application.test_configuration_use_cases import FakeConfigurationItemRepository


def _item() -> ConfigurationItem:
    return ConfigurationItem(
        installation_id=uuid4(),
        config_source="wp-config.php",
        key="WP_DEBUG",
        raw_value="false",
        is_flagged=False,
        flag_reason=None,
        is_present=True,
        last_seen_at=utcnow(),
    )


async def test_list_configuration_items_query_returns_empty_by_default() -> None:
    repo = FakeConfigurationItemRepository()
    query = ListConfigurationItemsQuery(repo)

    result = await query.execute(limit=50, offset=0)

    assert result == []


async def test_list_configuration_items_query_returns_seeded_item() -> None:
    repo = FakeConfigurationItemRepository()
    item = _item()
    await repo.add(item)
    query = ListConfigurationItemsQuery(repo)

    result = await query.execute(limit=50, offset=0)

    assert result == [item]
