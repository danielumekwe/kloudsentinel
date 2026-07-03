from __future__ import annotations

from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.domain.shared.entity import utcnow


def _item(**kwargs: object) -> ConfigurationItem:
    defaults: dict[str, object] = dict(
        installation_id=__import__("uuid").uuid4(),
        config_source="wp-config.php",
        key="WP_DEBUG",
        raw_value="false",
        is_flagged=False,
        flag_reason=None,
        is_present=True,
        last_seen_at=utcnow(),
    )
    defaults.update(kwargs)
    return ConfigurationItem(**defaults)  # type: ignore[arg-type]


async def test_mark_seen_updates_value_and_flag() -> None:
    item = _item(raw_value="false", is_flagged=False, flag_reason=None)
    at = utcnow()
    item.mark_seen(raw_value="true", is_flagged=True, flag_reason="Debug mode is enabled", at=at)

    assert item.raw_value == "true"
    assert item.is_flagged is True
    assert item.flag_reason == "Debug mode is enabled"
    assert item.is_present is True
    assert item.last_seen_at == at


async def test_mark_seen_reactivates_absent_item() -> None:
    item = _item(is_present=False)
    item.mark_seen(raw_value="true", is_flagged=False, flag_reason=None, at=utcnow())

    assert item.is_present is True


async def test_mark_absent_clears_presence() -> None:
    item = _item(is_present=True)
    at = utcnow()
    item.mark_absent(at=at)

    assert item.is_present is False
    assert item.last_seen_at == at


async def test_mark_absent_does_not_clear_value() -> None:
    item = _item(raw_value="true", is_flagged=True, flag_reason="some reason")
    item.mark_absent(at=utcnow())

    assert item.raw_value == "true"
    assert item.is_flagged is True
