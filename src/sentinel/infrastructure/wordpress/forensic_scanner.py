from __future__ import annotations

import hashlib
import re
from pathlib import Path

import structlog

from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.shared.value_objects import Severity
from sentinel.domain.wordpress.forensic.value_objects import WordPressForensicFinding
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner

logger = structlog.get_logger()

_PLUGIN_NAME_RE = re.compile(r"^[ \t*]*Plugin Name:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_THEME_NAME_RE = re.compile(r"^[ \t*]*Theme Name:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_UPLOAD_SCRIPT_SUFFIXES = (".php", ".phtml", ".php5", ".phar")
_HASH_CHUNK_SIZE = 1024 * 1024


def _hash_file(path: Path) -> str | None:
    """Best-effort sha256, computed only for a finding that already matched
    a malware rule (i.e. the file was already read once to check it) — lets
    ``RunWordPressForensicScanUseCase`` turn a CRITICAL finding into a
    quarantinable ``IntegrityFinding`` without any application-layer file
    I/O. Returns ``None`` rather than raising if the file vanished between
    the malware scan and this call."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


class WordPressForensicScanner:
    """WordPress-*structural* detection, layered on top of (not duplicating)
    the generic ``PhpMalwareScanner`` content rules every other scanner in
    this codebase already reuses:

    - fake plugin/theme: a directory under ``wp-content/plugins``/``themes``
      that has PHP files but no valid header — invisible to
      ``FilesystemWordPressExtensionScanner`` (it just skips headerless
      directories), a first-class finding here.
    - must-use plugins: always reported (rare on typical shared-hosting
      WordPress, and auto-loaded on every request with no "activation"
      step — classic persistence).
    - hidden PHP in uploads: ``wp-content/uploads`` is excluded from
      file-integrity monitoring (media libraries are huge/binary), which
      is exactly where webshells actually get dropped.
    - drop-ins: ``wp-content/db.php``/``object-cache.php``/
      ``advanced-cache.php`` are rare on shared hosting; presence alone is
      worth a report, content is also run through the malware scanner.
    """

    def __init__(
        self, *, php_malware_scanner: PhpMalwareScanner, dropin_relative_paths: list[str]
    ) -> None:
        self._php_malware_scanner = php_malware_scanner
        self._dropin_paths = dropin_relative_paths

    async def scan(self, installation: WordPressInstallation) -> list[WordPressForensicFinding]:
        root = Path(str(installation.absolute_path))
        findings: list[WordPressForensicFinding] = []
        findings.extend(await self._scan_fake_plugins(root))
        findings.extend(await self._scan_fake_themes(root))
        findings.extend(await self._scan_mu_plugins(root))
        findings.extend(await self._scan_hidden_uploads(root))
        findings.extend(await self._scan_dropins(root))
        return findings

    async def _scan_fake_plugins(self, root: Path) -> list[WordPressForensicFinding]:
        plugins_dir = root / "wp-content" / "plugins"
        return await self._scan_extension_directory(
            plugins_dir, root, name_pattern=_PLUGIN_NAME_RE, kind="plugin"
        )

    async def _scan_fake_themes(self, root: Path) -> list[WordPressForensicFinding]:
        themes_dir = root / "wp-content" / "themes"
        return await self._scan_extension_directory(
            themes_dir, root, name_pattern=_THEME_NAME_RE, kind="theme", header_file="style.css"
        )

    async def _scan_extension_directory(
        self,
        directory: Path,
        root: Path,
        *,
        name_pattern: re.Pattern[str],
        kind: str,
        header_file: str | None = None,
    ) -> list[WordPressForensicFinding]:
        if not directory.is_dir():
            return []
        try:
            entries = list(directory.iterdir())
        except OSError:
            return []

        findings: list[WordPressForensicFinding] = []
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue

            has_valid_header = self._has_valid_header(
                entry, name_pattern=name_pattern, header_file=header_file
            )
            php_files = self._php_files_in(entry)
            if has_valid_header or not php_files:
                continue

            any_matches = False
            for php_file in php_files:
                file_matches = await self._php_malware_scanner.scan_file(php_file)
                if not file_matches:
                    continue
                any_matches = True
                # One finding per matched file, not per directory — a
                # directory can't be quarantined (`FileRemediator` only
                # ever moves a single regular file), so a CRITICAL finding
                # needs to point at exactly the file auto-quarantine can
                # act on.
                findings.append(
                    WordPressForensicFinding(
                        finding_type=f"fake_{kind}",
                        relative_path=str(php_file.relative_to(root)),
                        description=(
                            f"PHP file under wp-content/{kind}s/{entry.name} matches malware "
                            f"rules; directory has no valid {kind} header — not visible to "
                            "normal inventory scanning"
                        ),
                        severity=Severity.CRITICAL,
                        matched_rule_ids=tuple(match.rule_id for match in file_matches),
                        sha256=_hash_file(php_file),
                    )
                )

            if not any_matches:
                findings.append(
                    WordPressForensicFinding(
                        finding_type=f"fake_{kind}",
                        relative_path=str(entry.relative_to(root)),
                        description=(
                            f"Directory under wp-content/{kind}s contains PHP files but no "
                            f"valid {kind} header — not visible to normal inventory scanning"
                        ),
                        severity=Severity.HIGH,
                        matched_rule_ids=(),
                    )
                )
        return findings

    def _has_valid_header(
        self, extension_dir: Path, *, name_pattern: re.Pattern[str], header_file: str | None
    ) -> bool:
        candidates: list[Path]
        if header_file is not None:
            candidates = [extension_dir / header_file]
        else:
            candidates = self._php_files_in(extension_dir)

        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            try:
                content = candidate.read_text(errors="ignore")
            except OSError:
                continue
            if name_pattern.search(content):
                return True
        return False

    def _php_files_in(self, directory: Path) -> list[Path]:
        try:
            return [
                entry
                for entry in directory.iterdir()
                if entry.suffix == ".php" and entry.is_file() and not entry.is_symlink()
            ]
        except OSError:
            return []

    async def _scan_mu_plugins(self, root: Path) -> list[WordPressForensicFinding]:
        mu_plugins_dir = root / "wp-content" / "mu-plugins"
        try:
            entries = list(mu_plugins_dir.iterdir())
        except OSError:
            return []

        findings: list[WordPressForensicFinding] = []
        for entry in entries:
            if entry.is_symlink() or not entry.is_file() or entry.suffix != ".php":
                continue
            matches = await self._php_malware_scanner.scan_file(entry)
            findings.append(
                WordPressForensicFinding(
                    finding_type="mu_plugin_present",
                    relative_path=str(entry.relative_to(root)),
                    description=(
                        "Must-use plugin present — auto-loaded on every request with no "
                        "activation step, a common persistence mechanism"
                    ),
                    severity=Severity.CRITICAL if matches else Severity.MEDIUM,
                    matched_rule_ids=tuple(match.rule_id for match in matches),
                    sha256=_hash_file(entry) if matches else None,
                )
            )
        return findings

    async def _scan_hidden_uploads(self, root: Path) -> list[WordPressForensicFinding]:
        uploads_dir = root / "wp-content" / "uploads"
        findings: list[WordPressForensicFinding] = []
        for path in self._walk_scripts(uploads_dir):
            matches = await self._php_malware_scanner.scan_file(path)
            if not matches:
                continue
            findings.append(
                WordPressForensicFinding(
                    finding_type="hidden_upload_script",
                    relative_path=str(path.relative_to(root)),
                    description="Script-like file found under wp-content/uploads matching malware rules",
                    severity=Severity.CRITICAL,
                    matched_rule_ids=tuple(match.rule_id for match in matches),
                    sha256=_hash_file(path),
                )
            )
        return findings

    def _walk_scripts(self, directory: Path) -> list[Path]:
        if not directory.is_dir():
            return []
        found: list[Path] = []
        try:
            entries = list(directory.iterdir())
        except OSError:
            return []
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                found.extend(self._walk_scripts(entry))
            elif entry.is_file() and entry.suffix.lower() in _UPLOAD_SCRIPT_SUFFIXES:
                found.append(entry)
        return found

    async def _scan_dropins(self, root: Path) -> list[WordPressForensicFinding]:
        findings: list[WordPressForensicFinding] = []
        for relative_path in self._dropin_paths:
            path = root / relative_path
            if not path.is_file() or path.is_symlink():
                continue
            matches = await self._php_malware_scanner.scan_file(path)
            findings.append(
                WordPressForensicFinding(
                    finding_type="dropin_present",
                    relative_path=relative_path,
                    description=(
                        f"{relative_path} is present — rare on typical shared-hosting "
                        "WordPress and a known malware-persistence drop-in point"
                    ),
                    severity=Severity.CRITICAL if matches else Severity.HIGH,
                    matched_rule_ids=tuple(match.rule_id for match in matches),
                    sha256=_hash_file(path) if matches else None,
                )
            )
        return findings
