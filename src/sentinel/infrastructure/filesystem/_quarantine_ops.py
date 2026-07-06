from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

from sentinel.domain.integrity.value_objects import QuarantinedFile
from sentinel.domain.shared.exceptions import FileRemediationError


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


def quarantine_file(source: Path, *, quarantine_dir: Path) -> QuarantinedFile:
    """Moves ``source`` into ``quarantine_dir`` under a random name, with the
    original mode/size captured for a later ``restore_file`` call. Refuses
    symlinks — a quarantine operation must only ever consume the bytes of a
    real file, never follow a link to somewhere else on disk."""
    if source.is_symlink() or not source.is_file():
        raise FileRemediationError(f"Not a regular file: {source}")

    try:
        stat = source.stat()
    except OSError as exc:
        raise FileRemediationError(f"Cannot stat {source}: {exc}") from exc

    destination = quarantine_dir / f"{uuid4().hex}_{source.name}"

    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.move(str(source), str(destination))
        destination.chmod(0o600)
    except OSError as exc:
        raise FileRemediationError(f"Cannot quarantine {source}: {exc}") from exc

    return QuarantinedFile(
        quarantine_path=str(destination),
        mode=format(stat.st_mode & 0o777, "03o"),
        size_bytes=stat.st_size,
    )


def restore_file(quarantine_path: str, *, destination: Path, mode: str) -> None:
    source = Path(quarantine_path)
    if source.is_symlink() or not source.is_file():
        raise FileRemediationError(f"Quarantined file missing: {source}")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        destination.chmod(int(mode, 8))
    except OSError as exc:
        raise FileRemediationError(f"Cannot restore to {destination}: {exc}") from exc


def purge_file(quarantine_path: str) -> None:
    path = Path(quarantine_path)
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise FileRemediationError(f"Cannot purge {path}: {exc}") from exc
