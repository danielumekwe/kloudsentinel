from __future__ import annotations

import httpx


class WordPressOrgChecksumsClient:
    """Fetches official per-release file checksums from WordPress.org's
    public checksums API. Called only to populate the local
    ``CoreChecksumRecord`` cache once per ``wp_version`` — never on the hot
    path of a routine integrity scan.
    """

    def __init__(
        self,
        *,
        base_url: str,
        locale: str,
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._locale = locale
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def fetch_checksums(self, wp_version: str) -> dict[str, str]:
        async with httpx.AsyncClient(
            timeout=self._timeout_seconds, transport=self._transport
        ) as client:
            response = await client.get(
                f"{self._base_url}/",
                params={"version": wp_version, "locale": self._locale},
            )
            response.raise_for_status()

        payload = response.json()
        checksums = payload.get("checksums")
        if not isinstance(checksums, dict):
            return {}
        return {str(path): str(sha256) for path, sha256 in checksums.items()}
