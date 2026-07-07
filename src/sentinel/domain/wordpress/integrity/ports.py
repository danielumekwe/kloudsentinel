from __future__ import annotations

from typing import Protocol

from sentinel.domain.shared.ports import Repository
from sentinel.domain.wordpress.integrity.entities import CoreChecksumRecord


class CoreChecksumRepository(Repository[CoreChecksumRecord], Protocol):
    async def get_by_version_and_path(
        self, wp_version: str, relative_path: str
    ) -> CoreChecksumRecord | None: ...

    async def list_by_version(self, wp_version: str) -> list[CoreChecksumRecord]: ...

    async def has_version(self, wp_version: str) -> bool: ...


class WordPressChecksumsClient(Protocol):
    """Fetches official per-release file checksums for one WordPress
    version. Decoupled from ``WordPressOrgChecksumsClient`` so the
    verification use case is testable without a real HTTP call."""

    async def fetch_checksums(self, wp_version: str) -> dict[str, str]: ...
