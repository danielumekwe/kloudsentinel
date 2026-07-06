from __future__ import annotations

from pathlib import Path
from typing import Protocol

from sentinel.domain.heuristics.value_objects import HeuristicMatch


class HeuristicScanner(Protocol):
    """Scans an arbitrary local directory (e.g. an extracted WordPress
    backup) for signature/heuristic malware indicators. Deliberately takes a
    raw ``Path`` rather than a ``CpanelAccount`` — offline archive scanning
    has no account, server, or baseline concept, just a directory on disk."""

    async def scan(self, root: Path) -> list[HeuristicMatch]: ...
