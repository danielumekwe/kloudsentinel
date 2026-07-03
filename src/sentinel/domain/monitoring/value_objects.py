from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.shared.entity import ValueObject


@dataclass(frozen=True)
class DiscoveredConfigItem(ValueObject):
    """Raw finding produced by the configuration scanner before persistence.

    ``config_source`` is the relative filename within the WordPress root
    (e.g. ``"wp-config.php"`` or ``".user.ini"``).  ``key`` is the
    constant / ini setting name.  ``is_flagged`` is True when the current
    value violates a known security rule."""

    config_source: str
    key: str
    raw_value: str | None
    is_flagged: bool
    flag_reason: str | None
