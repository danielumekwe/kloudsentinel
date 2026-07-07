from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from sentinel.config import Settings
from sentinel.infrastructure.persistence.database import Database
from tests.e2e.test_integrity_api import _seed_account, _seed_finding


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """SENTINEL_MODE=observe (the production default) — every mutation
    endpoint must refuse to act, proving Sentinel can never modify a
    customer's files while running in observation mode."""
    db_path = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        log_level="DEBUG",
        quarantine_root_directory=str(tmp_path / "quarantine"),
        mode="observe",
    )


async def test_quarantine_finding_is_blocked_in_observe_mode(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/quarantine",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 403


async def test_restore_finding_is_blocked_in_observe_mode(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/restore",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 403


async def test_delete_finding_is_blocked_in_observe_mode(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/delete",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 403


def test_observe_mode_check_runs_before_finding_lookup(client: TestClient, api_key: str) -> None:
    """Even a nonexistent finding_id must be rejected with 403, not 404 —
    proving the mode guard is checked before any database lookup, not
    bypassable by probing for real IDs."""
    response = client.post(
        f"/api/v1/integrity/findings/{uuid4()}/quarantine",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 403


def test_list_findings_still_works_in_observe_mode(client: TestClient, api_key: str) -> None:
    """Read-only endpoints are never gated by SENTINEL_MODE."""
    response = client.get(
        "/api/v1/integrity/findings", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
