from __future__ import annotations

from uuid import uuid4

from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.shared.entity import utcnow


def _plugin(*, is_present: bool = True) -> InstalledPlugin:
    return InstalledPlugin(
        installation_id=uuid4(),
        slug="woocommerce",
        name="WooCommerce",
        version="8.0.0",
        is_present=is_present,
        last_seen_at=utcnow(),
    )


def _theme(*, is_present: bool = True) -> InstalledTheme:
    return InstalledTheme(
        installation_id=uuid4(),
        slug="twentytwentyfour",
        name="Twenty Twenty-Four",
        version="1.0.0",
        is_present=is_present,
        last_seen_at=utcnow(),
    )


def test_plugin_mark_seen_updates_fields_and_sets_present() -> None:
    plugin = _plugin(is_present=False)
    at = utcnow()

    plugin.mark_seen(name="WooCommerce", version="8.1.0", at=at)

    assert plugin.version == "8.1.0"
    assert plugin.is_present is True
    assert plugin.last_seen_at == at


def test_plugin_mark_absent_clears_present_flag() -> None:
    plugin = _plugin(is_present=True)
    at = utcnow()

    plugin.mark_absent(at=at)

    assert plugin.is_present is False
    assert plugin.last_seen_at == at


def test_plugin_mark_seen_on_absent_plugin_reactivates() -> None:
    plugin = _plugin(is_present=False)

    plugin.mark_seen(name="WooCommerce", version="8.2.0", at=utcnow())

    assert plugin.is_present is True
    assert plugin.version == "8.2.0"


def test_plugin_mark_seen_updates_name_and_version() -> None:
    plugin = _plugin()

    plugin.mark_seen(name="WooCommerce Renamed", version=None, at=utcnow())

    assert plugin.name == "WooCommerce Renamed"
    assert plugin.version is None


def test_plugin_mark_seen_touches_updated_at() -> None:
    plugin = _plugin()
    original_updated_at = plugin.updated_at

    plugin.mark_seen(name="WooCommerce", version="8.0.0", at=utcnow())

    assert plugin.updated_at >= original_updated_at


def test_theme_mark_seen_updates_fields_and_sets_present() -> None:
    theme = _theme(is_present=False)
    at = utcnow()

    theme.mark_seen(name="Twenty Twenty-Four", version="1.1.0", at=at)

    assert theme.version == "1.1.0"
    assert theme.is_present is True
    assert theme.last_seen_at == at


def test_theme_mark_absent_clears_present_flag() -> None:
    theme = _theme(is_present=True)
    at = utcnow()

    theme.mark_absent(at=at)

    assert theme.is_present is False
    assert theme.last_seen_at == at


def test_theme_mark_seen_on_absent_theme_reactivates() -> None:
    theme = _theme(is_present=False)

    theme.mark_seen(name="Twenty Twenty-Four", version="2.0.0", at=utcnow())

    assert theme.is_present is True
    assert theme.version == "2.0.0"
