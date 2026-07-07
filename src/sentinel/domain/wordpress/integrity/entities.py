from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sentinel.domain.shared.entity import BaseEntity


@dataclass(kw_only=True)
class CoreChecksumRecord(BaseEntity):
    """One official WordPress core file's known-good hash for a specific
    release, as published by WordPress.org's checksums API.

    Reference data, not per-account: fetched and cached once per
    ``wp_version`` and reused by every installation running that version,
    so a routine integrity scan never has to call out to WordPress.org
    itself. Immutable once recorded — a new release gets new rows, it never
    mutates an existing one.
    """

    wp_version: str
    relative_path: str
    sha256: str
    fetched_at: datetime
