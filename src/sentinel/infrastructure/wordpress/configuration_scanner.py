from __future__ import annotations

import re
from pathlib import Path

import structlog

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.monitoring.value_objects import DiscoveredConfigItem

logger = structlog.get_logger()

_WP_CONFIG_SOURCE = "wp-config.php"
_USER_INI_SOURCE = ".user.ini"

# Matches: define( 'CONSTANT_NAME', value )  (single or double quotes)
_DEFINE_RE = re.compile(
    r"""define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*(.+?)\s*\)""",
    re.IGNORECASE,
)
# Matches: $table_prefix = 'value';
_TABLE_PREFIX_RE = re.compile(
    r"""^\s*\$table_prefix\s*=\s*['"](.+?)['"]\s*;""",
    re.MULTILINE,
)
# Matches: setting = value  (in .user.ini)
_INI_SETTING_RE = re.compile(
    r"""^\s*([a-z_][a-z0-9_]*)\s*=\s*(.+?)\s*$""",
    re.MULTILINE | re.IGNORECASE,
)

# wp-config.php: constants where presence of `true` is the bad state
_FLAGGED_WHEN_TRUE: dict[str, str] = {
    "WP_DEBUG": "Debug mode is enabled",
    "WP_DEBUG_LOG": "Debug logging is enabled",
    "WP_DEBUG_DISPLAY": "Debug output is displayed publicly",
}

# wp-config.php: constants where absence or `false` is the bad state
_FLAGGED_WHEN_ABSENT_OR_FALSE: dict[str, str] = {
    "DISALLOW_FILE_EDIT": "File editor is not disabled (DISALLOW_FILE_EDIT)",
    "DISALLOW_FILE_MODS": "Plugin and theme updates are not disabled (DISALLOW_FILE_MODS)",
    "FORCE_SSL_ADMIN": "Admin panel does not enforce HTTPS (FORCE_SSL_ADMIN)",
}

_DEFAULT_TABLE_PREFIX = "wp_"

# .user.ini: settings where a truthy value is flagged
_INI_FLAGGED_WHEN_TRUTHY: dict[str, str] = {
    "display_errors": "PHP error display is enabled",
    "allow_url_fopen": "PHP remote file fetching is enabled",
    "allow_url_include": "PHP remote code inclusion is enabled",
}


def _normalize_php_value(raw: str) -> str:
    """Normalize a PHP literal to a plain string for storage and comparison."""
    raw = raw.strip()
    lower = raw.lower()
    if lower in ("true", "false", "null"):
        return lower
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        return raw[1:-1]
    return raw


def _is_php_true(value: str) -> bool:
    return value.lower() == "true"


def _is_ini_truthy(value: str) -> bool:
    return value.strip().lower() in ("on", "1", "true", "yes")


def _parse_wp_config(text: str) -> list[DiscoveredConfigItem]:
    items: list[DiscoveredConfigItem] = []
    defines: dict[str, str] = {}

    for match in _DEFINE_RE.finditer(text):
        key = match.group(1).upper()
        normalized = _normalize_php_value(match.group(2))
        defines[key] = normalized

    # Constants flagged when true
    for key, reason in _FLAGGED_WHEN_TRUE.items():
        if key in defines:
            value = defines[key]
            flagged = _is_php_true(value)
            items.append(
                DiscoveredConfigItem(
                    config_source=_WP_CONFIG_SOURCE,
                    key=key,
                    raw_value=value,
                    is_flagged=flagged,
                    flag_reason=reason if flagged else None,
                )
            )

    # Constants flagged when absent or false
    for key, reason in _FLAGGED_WHEN_ABSENT_OR_FALSE.items():
        opt_value: str | None = defines.get(key)
        if opt_value is None:
            # Absent → flagged
            items.append(
                DiscoveredConfigItem(
                    config_source=_WP_CONFIG_SOURCE,
                    key=key,
                    raw_value=None,
                    is_flagged=True,
                    flag_reason=reason,
                )
            )
        else:
            flagged = not _is_php_true(opt_value)
            items.append(
                DiscoveredConfigItem(
                    config_source=_WP_CONFIG_SOURCE,
                    key=key,
                    raw_value=opt_value,
                    is_flagged=flagged,
                    flag_reason=reason if flagged else None,
                )
            )

    # Table prefix
    prefix_match = _TABLE_PREFIX_RE.search(text)
    if prefix_match:
        prefix = prefix_match.group(1)
        flagged = prefix == _DEFAULT_TABLE_PREFIX
        items.append(
            DiscoveredConfigItem(
                config_source=_WP_CONFIG_SOURCE,
                key="table_prefix",
                raw_value=prefix,
                is_flagged=flagged,
                flag_reason="Default table prefix in use" if flagged else None,
            )
        )

    return items


def _parse_user_ini(text: str) -> list[DiscoveredConfigItem]:
    items: list[DiscoveredConfigItem] = []
    settings: dict[str, str] = {}

    for match in _INI_SETTING_RE.finditer(text):
        settings[match.group(1).lower()] = match.group(2).strip()

    for key, reason in _INI_FLAGGED_WHEN_TRUTHY.items():
        if key in settings:
            value = settings[key]
            flagged = _is_ini_truthy(value)
            items.append(
                DiscoveredConfigItem(
                    config_source=_USER_INI_SOURCE,
                    key=key,
                    raw_value=value,
                    is_flagged=flagged,
                    flag_reason=reason if flagged else None,
                )
            )

    return items


class FilesystemWordPressConfigurationScanner:
    """Reads security-relevant configuration from a WordPress installation's
    filesystem.  Parses ``wp-config.php`` for PHP constants and
    ``$table_prefix``, and ``.user.ini`` for PHP ini overrides.

    Missing files are silently skipped (logged at debug level).  Read
    errors are logged as warnings and skipped without raising."""

    async def scan(self, installation: WordPressInstallation) -> list[DiscoveredConfigItem]:
        root = Path(str(installation.absolute_path))
        items: list[DiscoveredConfigItem] = []

        wp_config = root / "wp-config.php"
        try:
            text = wp_config.read_text(encoding="utf-8", errors="replace")
            items.extend(_parse_wp_config(text))
        except FileNotFoundError:
            logger.debug(
                "wp_config_not_found",
                path=str(wp_config),
                installation_id=str(installation.id),
            )
        except OSError:
            logger.warning(
                "wp_config_read_error",
                path=str(wp_config),
                installation_id=str(installation.id),
                exc_info=True,
            )

        user_ini = root / ".user.ini"
        try:
            text = user_ini.read_text(encoding="utf-8", errors="replace")
            items.extend(_parse_user_ini(text))
        except FileNotFoundError:
            logger.debug(
                "user_ini_not_found",
                path=str(user_ini),
                installation_id=str(installation.id),
            )
        except OSError:
            logger.warning(
                "user_ini_read_error",
                path=str(user_ini),
                installation_id=str(installation.id),
                exc_info=True,
            )

        return items
