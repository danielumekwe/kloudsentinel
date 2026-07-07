from __future__ import annotations

import hashlib
import hmac
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentinel.bootstrap import create_app
from sentinel.config import Settings
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models import AdminUserModel

_SHARED_SECRET = "test-whm-plugin-secret"
_WHM_USER = "root"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Overrides the conftest ``settings`` fixture — every test in this file
    needs ``whm_plugin_shared_secret`` set, since the bridge endpoint
    refuses every request otherwise (see auth.py's create_whm_bridged_session)."""
    db_path = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        log_level="DEBUG",
        whm_plugin_shared_secret=_SHARED_SECRET,
    )


def _sign(user: str, timestamp: int, secret: str = _SHARED_SECRET) -> str:
    return hmac.new(
        secret.encode("utf-8"), f"{user}:{timestamp}".encode(), hashlib.sha256
    ).hexdigest()


def _loopback_client(settings: Settings) -> TestClient:
    """A TestClient whose ``request.client.host`` is 127.0.0.1 — the
    default TestClient reports "testclient", which the bridge endpoint
    correctly rejects (see the non-loopback test below), so tests
    exercising the accepted path need this instead."""
    return TestClient(create_app(settings), client=("127.0.0.1", 12345))


def test_whm_session_rejects_non_loopback_origin(client: TestClient, database: Database) -> None:
    del database
    timestamp = int(time.time())
    response = client.post(
        "/dashboard/whm-session",
        headers={
            "X-Sentinel-WHM-User": _WHM_USER,
            "X-Sentinel-WHM-Timestamp": str(timestamp),
            "X-Sentinel-WHM-Signature": _sign(_WHM_USER, timestamp),
        },
    )
    assert response.status_code == 403


def test_whm_session_rejects_missing_shared_secret(database: Database) -> None:
    """Even from loopback, with the shared secret unconfigured (the
    Settings default) the endpoint must refuse rather than accept a
    signature nothing can actually validate."""
    unconfigured_settings = Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
        log_level="DEBUG",
    )
    del database
    with _loopback_client(unconfigured_settings) as unconfigured_client:
        timestamp = int(time.time())
        response = unconfigured_client.post(
            "/dashboard/whm-session",
            headers={
                "X-Sentinel-WHM-User": _WHM_USER,
                "X-Sentinel-WHM-Timestamp": str(timestamp),
                "X-Sentinel-WHM-Signature": _sign(_WHM_USER, timestamp),
            },
        )
        assert response.status_code == 403


def test_whm_session_rejects_stale_timestamp(settings: Settings, database: Database) -> None:
    del database
    with _loopback_client(settings) as loopback_client:
        stale_timestamp = int(time.time()) - 120
        response = loopback_client.post(
            "/dashboard/whm-session",
            headers={
                "X-Sentinel-WHM-User": _WHM_USER,
                "X-Sentinel-WHM-Timestamp": str(stale_timestamp),
                "X-Sentinel-WHM-Signature": _sign(_WHM_USER, stale_timestamp),
            },
        )
        assert response.status_code == 403


def test_whm_session_rejects_invalid_signature(settings: Settings, database: Database) -> None:
    del database
    with _loopback_client(settings) as loopback_client:
        timestamp = int(time.time())
        response = loopback_client.post(
            "/dashboard/whm-session",
            headers={
                "X-Sentinel-WHM-User": _WHM_USER,
                "X-Sentinel-WHM-Timestamp": str(timestamp),
                "X-Sentinel-WHM-Signature": "0" * 64,
            },
        )
        assert response.status_code == 403


async def test_whm_session_happy_path_auto_provisions_admin_user(
    settings: Settings, database: Database
) -> None:
    with _loopback_client(settings) as loopback_client:
        timestamp = int(time.time())
        response = loopback_client.post(
            "/dashboard/whm-session",
            headers={
                "X-Sentinel-WHM-User": _WHM_USER,
                "X-Sentinel-WHM-Timestamp": str(timestamp),
                "X-Sentinel-WHM-Signature": _sign(_WHM_USER, timestamp),
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["session_token"]
        assert body["csrf_token"]
        assert body["expires_in"] > 0

    async with database.session() as session:
        result = await session.execute(
            select(AdminUserModel).where(AdminUserModel.username == f"whm:{_WHM_USER}")
        )
        admin_user = result.scalar_one()
        assert admin_user.is_active
