from __future__ import annotations

import hashlib
import os
import pwd
from pathlib import Path

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.ports import CpanelAccountRepository
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.forensics.entities import TempFileObservation
from sentinel.domain.forensics.value_objects import ProcessContext, TempFileVerdict
from sentinel.domain.heuristics.value_objects import HeuristicMatch
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import ValidationError
from sentinel.domain.shared.value_objects import AbsoluteFilePath, Severity, Sha256Hash
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner
from sentinel.infrastructure.mime import guess_mime_type

_HASH_CHUNK_SIZE = 65_536
_PROC_ROOT = Path("/proc")


class FilesystemTempFileScanner:
    """Watches a fixed set of directories (``/tmp``, ``/var/tmp``,
    ``/dev/shm`` by default) for script-like files and classifies each one
    using ``PhpMalwareScanner``'s existing behavioral rules — the same
    signatures the offline archive scanner uses, just pointed at a live temp
    directory instead of an extracted backup.

    Process/network context is best-effort via ``/proc`` (Linux-only,
    silently empty everywhere else or on any permission failure — a live
    process is often long gone by the time a poll-based scan catches its
    output file anyway, so this is a bonus signal, never a requirement).
    """

    def __init__(
        self,
        *,
        directories: list[str],
        watched_extensions: list[str],
        php_malware_scanner: PhpMalwareScanner,
        account_repository: CpanelAccountRepository,
    ) -> None:
        self._directories = [Path(d) for d in directories]
        self._watched_extensions = {ext.lower() for ext in watched_extensions}
        self._php_malware_scanner = php_malware_scanner
        self._accounts = account_repository

    async def scan(self) -> list[TempFileObservation]:
        observations: list[TempFileObservation] = []
        for directory in self._directories:
            observations.extend(await self._scan_directory(directory))
        return observations

    async def _scan_directory(self, directory: Path) -> list[TempFileObservation]:
        try:
            entries = list(directory.iterdir())
        except OSError:
            return []

        observations: list[TempFileObservation] = []
        for entry in entries:
            if entry.is_symlink() or not entry.is_file():
                continue
            if entry.suffix.lower() not in self._watched_extensions:
                continue
            observations.append(await self._observe(entry))
        return observations

    async def _observe(self, path: Path) -> TempFileObservation:
        now = utcnow()
        try:
            stat = path.stat()
            sha256 = Sha256Hash(value=_sha256_of(path))
            size_bytes = stat.st_size
            owner = _owner_of(stat.st_uid)
            file_permissions = format(stat.st_mode & 0o777, "03o")
        except OSError:
            sha256 = None
            size_bytes = 0
            owner = "unknown"
            file_permissions = None

        matches = await self._php_malware_scanner.scan_file(path)
        verdict, reason = _classify(matches)
        account = await self._resolve_account(owner)

        return TempFileObservation(
            absolute_path=AbsoluteFilePath(value=str(path)),
            sha256=sha256,
            owner=owner,
            size_bytes=size_bytes,
            verdict=verdict,
            verdict_reason=reason,
            matched_rule_ids=tuple(match.rule_id for match in matches),
            process=_process_context_for(path),
            account_id=account.id if account is not None else None,
            detected_at=now,
            file_permissions=file_permissions,
            mime_type=guess_mime_type(path.name),
            server_id=account.server_id if account is not None else None,
        )

    async def _resolve_account(self, owner: str) -> CpanelAccount | None:
        try:
            username = LinuxUsername(value=owner)
        except ValidationError:
            return None
        return await self._accounts.get_by_username(username)


def _classify(matches: list[HeuristicMatch]) -> tuple[TempFileVerdict, str]:
    if not matches:
        return TempFileVerdict.LEGITIMATE, "No heuristic rules matched"

    top_match = max(matches, key=lambda match: match.severity.rank)
    if top_match.severity.rank >= Severity.HIGH.rank:
        return TempFileVerdict.MALICIOUS, top_match.description
    return TempFileVerdict.SUSPICIOUS, top_match.description


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _owner_of(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return str(uid)


def _process_context_for(path: Path) -> ProcessContext | None:
    """Best-effort: walks ``/proc/<pid>/fd`` looking for a process with
    ``path`` open. Returns ``None`` on any non-Linux host, permission
    failure, or when no process currently holds the file open — all
    equally normal outcomes for a poll-based scan.

    Network connections are deliberately left empty rather than
    cross-referencing ``/proc/net/tcp`` socket inodes against file
    descriptors — a heavier, unverified piece of complexity deferred until
    the simpler file-based evidence here has proven useful in practice.
    """
    if not _PROC_ROOT.is_dir():
        return None

    target = str(path)
    try:
        pids = [entry.name for entry in _PROC_ROOT.iterdir() if entry.name.isdigit()]
    except OSError:
        return None

    for pid in pids:
        pid_dir = _PROC_ROOT / pid
        open_files = _open_files_of(pid_dir)
        if target not in open_files:
            continue

        return ProcessContext(
            pid=int(pid),
            ppid=_ppid_of(pid_dir),
            executable_path=_executable_of(pid_dir),
            command_line=_command_line_of(pid_dir),
            open_files=tuple(open_files),
            network_connections=(),
        )
    return None


def _open_files_of(pid_dir: Path) -> list[str]:
    try:
        entries = list((pid_dir / "fd").iterdir())
    except OSError:
        return []

    files: list[str] = []
    for entry in entries:
        try:
            files.append(os.readlink(entry))
        except OSError:
            continue
    return files


def _command_line_of(pid_dir: Path) -> str | None:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return None
    text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    return text or None


def _executable_of(pid_dir: Path) -> str | None:
    try:
        return os.readlink(pid_dir / "exe")
    except OSError:
        return None


def _ppid_of(pid_dir: Path) -> int | None:
    try:
        status = (pid_dir / "status").read_text(errors="replace")
    except OSError:
        return None
    for line in status.splitlines():
        if line.startswith("PPid:"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None
