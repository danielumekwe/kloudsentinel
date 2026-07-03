from __future__ import annotations

import re
from pathlib import Path

import structlog

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import DiscoveredWordPressInstallation
from sentinel.domain.shared.value_objects import AbsoluteFilePath

logger = structlog.get_logger()

_VERSION_PATTERN = re.compile(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]")
_MULTISITE_PATTERN = re.compile(r"define\s*\(\s*['\"]MULTISITE['\"]\s*,\s*true\s*\)", re.IGNORECASE)


class FilesystemWordPressDetector:
    """Detects WordPress installations under a cPanel account's home
    directory by walking the filesystem for ``wp-includes/version.php`` —
    its presence is WordPress's own reliable installation signature, more
    robust than guessing from directory naming conventions.

    The walk is depth-bounded and skips symlinks: home directories can
    contain arbitrarily large upload trees, and a bounded, non-recursive-
    through-symlinks walk keeps one account's installations from a runaway
    scan affecting the rest of a discovery pass.

    Domain attribution is intentionally limited in this phase: an install
    directly under ``public_html`` is attributed to the account's primary
    domain; anything else (subdirectory installs, addon/subdomain docroots)
    is left with ``domain=None``. Correctly resolving those requires parsing
    cPanel's per-account vhost userdata, which is a larger, separate piece of
    work than "detect that WordPress exists here."
    """

    def __init__(self, *, max_depth: int = 4) -> None:
        self._max_depth = max_depth

    async def detect(self, account: CpanelAccount) -> list[DiscoveredWordPressInstallation]:
        home = Path(str(account.home_directory))
        if not home.is_dir():
            logger.warning("account_home_missing", home_directory=str(home))
            return []

        findings = []
        for version_file in self._find_version_files(home, depth=0):
            install_root = version_file.parent.parent
            wp_version = self._read_version(version_file)
            is_multisite = self._detect_multisite(install_root)
            domain = account.primary_domain if install_root == home / "public_html" else None

            findings.append(
                DiscoveredWordPressInstallation(
                    absolute_path=AbsoluteFilePath(value=str(install_root)),
                    domain=domain,
                    wp_version=wp_version,
                    is_multisite=is_multisite,
                )
            )

        return findings

    def _find_version_files(self, directory: Path, *, depth: int) -> list[Path]:
        if depth > self._max_depth:
            return []

        candidate = directory / "wp-includes" / "version.php"
        if candidate.is_file():
            return [candidate]

        found: list[Path] = []
        try:
            entries = list(directory.iterdir())
        except (PermissionError, OSError):
            return []

        for entry in entries:
            if not entry.is_dir() or entry.is_symlink():
                continue
            found.extend(self._find_version_files(entry, depth=depth + 1))
        return found

    def _read_version(self, version_file: Path) -> str | None:
        try:
            content = version_file.read_text(errors="ignore")
        except OSError:
            return None
        match = _VERSION_PATTERN.search(content)
        return match.group(1) if match else None

    def _detect_multisite(self, install_root: Path) -> bool:
        wp_config = install_root / "wp-config.php"
        try:
            content = wp_config.read_text(errors="ignore")
        except OSError:
            return False
        return bool(_MULTISITE_PATTERN.search(content))
