from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from sentinel.domain.integrity.value_objects import QuarantinedFile
from sentinel.domain.shared.exceptions import FileRemediationError
from sentinel.domain.shared.value_objects import Severity

_HASH_CHUNK_SIZE = 1024 * 1024
_METADATA_FILENAME = "metadata.json"

#: Deterministic severity -> score mapping shown to operators alongside a
#: quarantined file. Not a machine-learned confidence value — Sentinel has
#: no ML scoring anywhere — just a stable, human-readable projection of the
#: same ``Severity`` already assigned by whichever scanner raised the
#: finding.
_MALWARE_SCORE_BY_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 80,
    Severity.MEDIUM: 60,
    Severity.LOW: 40,
    Severity.INFO: 20,
}


def malware_score(severity: Severity) -> int:
    return _MALWARE_SCORE_BY_SEVERITY[severity]


def resolve_contained(path: Path, *, root: Path, description: str) -> Path:
    """Resolves ``path`` and asserts it falls under ``root`` once symlinks are
    followed.

    ``RelativeFilePath`` already rejects ``..`` segments, but that only
    guards against traversal spelled out in the path string itself — it
    can't catch a path that *looks* well-behaved but passes through an
    intermediate directory that is a symlink pointing outside ``root``
    (e.g. a compromised account replacing ``public_html/uploads`` with a
    symlink to ``/etc``). Resolving and checking containment here is what
    actually closes that gap before any move/delete touches disk.
    """
    resolved_root = root.resolve()
    try:
        resolved = path.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise FileRemediationError(f"Cannot resolve {description}: {exc}") from exc

    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise FileRemediationError(
            f"{description} escapes expected root {resolved_root}: {resolved}"
        )
    return resolved


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quarantine_file(
    source: Path,
    *,
    quarantine_dir: Path,
    detection_reason: str,
    severity: Severity,
    detected_at: datetime,
) -> QuarantinedFile:
    """Moves ``source`` into its own incident folder under ``quarantine_dir``,
    named ``{timestamp}-{filename}``, alongside a ``metadata.json`` sidecar
    recording the original path, hash, detection reason, severity/score, and
    ownership — everything a later ``restore_file``/``read_metadata`` call
    needs, without relying on the database being reachable to inspect a
    quarantined file. Refuses symlinks — a quarantine operation must only
    ever consume the bytes of a real file, never follow a link to somewhere
    else on disk."""
    if source.is_symlink() or not source.is_file():
        raise FileRemediationError(f"Not a regular file: {source}")

    try:
        stat = source.stat()
        sha256 = _hash_file(source)
    except OSError as exc:
        raise FileRemediationError(f"Cannot read {source}: {exc}") from exc

    original_path = str(source)
    folder_name = f"{detected_at:%Y%m%dT%H%M%SZ}-{source.name}"
    incident_dir = quarantine_dir / folder_name
    if incident_dir.exists():
        incident_dir = quarantine_dir / f"{folder_name}-{uuid4().hex[:8]}"

    mode = format(stat.st_mode & 0o777, "03o")
    try:
        incident_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        destination = incident_dir / source.name
        shutil.move(str(source), str(destination))
        destination.chmod(0o600)

        metadata_path = incident_dir / _METADATA_FILENAME
        metadata_path.write_text(
            json.dumps(
                {
                    "original_path": original_path,
                    "filename": source.name,
                    "sha256": sha256,
                    "detection_reason": detection_reason,
                    "severity": severity.value,
                    "malware_score": malware_score(severity),
                    "quarantined_at": detected_at.isoformat(),
                    "mode": mode,
                    "owner_uid": stat.st_uid,
                    "owner_gid": stat.st_gid,
                    "size_bytes": stat.st_size,
                },
                indent=2,
            )
        )
        metadata_path.chmod(0o600)
    except OSError as exc:
        raise FileRemediationError(f"Cannot quarantine {source}: {exc}") from exc

    return QuarantinedFile(
        quarantine_path=str(incident_dir),
        mode=mode,
        size_bytes=stat.st_size,
        owner_uid=stat.st_uid,
        owner_gid=stat.st_gid,
    )


def read_metadata(quarantine_path: str) -> dict[str, object]:
    metadata_path = Path(quarantine_path) / _METADATA_FILENAME
    try:
        contents: dict[str, object] = json.loads(metadata_path.read_text())
    except OSError as exc:
        raise FileRemediationError(f"Cannot read quarantine metadata: {exc}") from exc
    return contents


def quarantined_file_path(quarantine_path: str) -> Path:
    folder = Path(quarantine_path)
    try:
        candidates = [p for p in folder.iterdir() if p.name != _METADATA_FILENAME]
    except OSError as exc:
        raise FileRemediationError(f"Cannot read quarantine folder {folder}: {exc}") from exc
    if len(candidates) != 1:
        raise FileRemediationError(
            f"Expected exactly one quarantined file in {folder}, found {len(candidates)}"
        )
    return candidates[0]


def restore_file(
    quarantine_path: str,
    *,
    destination: Path,
    mode: str,
    owner_uid: int | None,
    owner_gid: int | None,
) -> None:
    folder = Path(quarantine_path)
    if not folder.is_dir():
        raise FileRemediationError(f"Quarantine folder missing: {folder}")
    source = quarantined_file_path(quarantine_path)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        destination.chmod(int(mode, 8))
        if owner_uid is not None and owner_gid is not None:
            with contextlib.suppress(PermissionError):
                os.chown(destination, owner_uid, owner_gid)
        shutil.rmtree(folder, ignore_errors=True)
    except OSError as exc:
        raise FileRemediationError(f"Cannot restore to {destination}: {exc}") from exc


def purge_folder(quarantine_path: str) -> None:
    folder = Path(quarantine_path)
    try:
        shutil.rmtree(folder)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise FileRemediationError(f"Cannot purge {folder}: {exc}") from exc
