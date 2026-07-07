from __future__ import annotations

import httpx
import pytest

from sentinel.infrastructure.wordpress.core_checksums import WordPressOrgChecksumsClient


def _client(handler) -> WordPressOrgChecksumsClient:  # type: ignore[no-untyped-def]
    return WordPressOrgChecksumsClient(
        base_url="https://api.wordpress.org/core/checksums/1.0/",
        locale="en_US",
        transport=httpx.MockTransport(handler),
    )


async def test_fetch_checksums_parses_checksums_payload() -> None:
    captured_params: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_params.update(dict(request.url.params))
        return httpx.Response(200, json={"checksums": {"wp-load.php": "a" * 64}})

    checksums = await _client(handler).fetch_checksums("6.5.2")

    assert checksums == {"wp-load.php": "a" * 64}
    assert captured_params == {"version": "6.5.2", "locale": "en_US"}


async def test_fetch_checksums_returns_empty_dict_for_missing_checksums_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": "unknown release"})

    checksums = await _client(handler).fetch_checksums("0.0.0")

    assert checksums == {}


async def test_fetch_checksums_raises_on_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with pytest.raises(httpx.HTTPStatusError):
        await _client(handler).fetch_checksums("6.5.2")
