from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models.discovery import (
    CpanelAccountModel,
    ServerModel,
    WordPressInstallationModel,
)


async def _seed_account(database: Database, *, username: str) -> None:
    now = utcnow()
    async with database.session() as session:
        server = ServerModel(
            id=uuid4(),
            hostname=f"host-{uuid4().hex}.example.com",
            os_info="Linux 6.1",
            agent_version="0.1.0",
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(server)
        await session.flush()

        account = CpanelAccountModel(
            id=uuid4(),
            server_id=server.id,
            username=username,
            primary_domain="example.com",
            home_directory=f"/home/{username}",
            is_suspended=False,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(account)
        await session.flush()

        installation = WordPressInstallationModel(
            id=uuid4(),
            cpanel_account_id=account.id,
            absolute_path=f"/home/{username}/public_html",
            domain="example.com",
            wp_version="6.5",
            is_multisite=False,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(installation)
        await session.commit()


def test_list_accounts_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/accounts")
    assert response.status_code == 401


async def test_list_accounts_returns_seeded_account(
    client: TestClient, database: Database, api_key: str
) -> None:
    await _seed_account(database, username="examplebob")

    response = client.get("/api/v1/accounts", headers={"Authorization": f"Bearer {api_key}"})

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert len(body["data"]) == 1
    assert body["data"][0]["username"] == "examplebob"
    assert "meta" in body and "pagination" in body


def test_list_installations_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/installations")
    assert response.status_code == 401


async def test_list_installations_returns_seeded_installation(
    client: TestClient, database: Database, api_key: str
) -> None:
    await _seed_account(database, username="examplebob")

    response = client.get("/api/v1/installations", headers={"Authorization": f"Bearer {api_key}"})

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["absolute_path"] == "/home/examplebob/public_html"
    assert body["data"][0]["wp_version"] == "6.5"


async def test_list_accounts_pagination_limit(
    client: TestClient, database: Database, api_key: str
) -> None:
    await _seed_account(database, username="examplebob")
    await _seed_account(database, username="exampleann")

    response = client.get(
        "/api/v1/accounts",
        params={"limit": 1},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["pagination"]["has_next"] is True
    assert body["pagination"]["cursor_next"] is not None
