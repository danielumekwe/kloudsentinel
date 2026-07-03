from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.shared.entity import ValueObject


@dataclass(frozen=True, kw_only=True)
class DiscoveredPlugin(ValueObject):
    """Raw finding produced by a ``WordPressExtensionScanner`` adapter for a
    single plugin directory, before reconciliation against persisted state."""

    slug: str
    name: str
    version: str | None


@dataclass(frozen=True, kw_only=True)
class DiscoveredTheme(ValueObject):
    """Raw finding produced by a ``WordPressExtensionScanner`` adapter for a
    single theme directory, before reconciliation against persisted state."""

    slug: str
    name: str
    version: str | None
