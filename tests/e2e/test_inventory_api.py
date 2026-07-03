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
from sentinel.infrastructure.persistence.models.inventory import (
    InstalledPluginModel,
    InstalledThemeModel,
)


async def _seed_installation(database: Database, *, username: str) -> str:
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
            wp_version="6.4.0",
            is_multisite=False,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(installation)
        await session.commit()
        return str(installation.id)


async def _seed_plugin(database: Database, *, installation_id: str) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            InstalledPluginModel(
                id=uuid4(),
                installation_id=installation_id,
                slug="woocommerce",
                name="WooCommerce",
                version="8.0.0",
                is_present=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


async def _seed_theme(database: Database, *, installation_id: str) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            InstalledThemeModel(
                id=uuid4(),
                installation_id=installation_id,
                slug="twentytwentyfour",
                name="Twenty Twenty-Four",
                version="1.0.0",
                is_present=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


def test_list_plugins_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/inventory/plugins")
    assert response.status_code == 401


def test_list_themes_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/inventory/themes")
    assert response.status_code == 401


async def test_list_plugins_returns_seeded_plugin(
    client: TestClient, database: Database, api_key: str
) -> None:
    installation_id = await _seed_installation(database, username="examplebob")
    await _seed_plugin(database, installation_id=installation_id)

    response = client.get(
        "/api/v1/inventory/plugins", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["slug"] == "woocommerce"
    assert body["data"][0]["name"] == "WooCommerce"
    assert body["data"][0]["version"] == "8.0.0"
    assert body["data"][0]["is_present"] is True


async def test_list_themes_returns_seeded_theme(
    client: TestClient, database: Database, api_key: str
) -> None:
    installation_id = await _seed_installation(database, username="examplebob")
    await _seed_theme(database, installation_id=installation_id)

    response = client.get(
        "/api/v1/inventory/themes", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["slug"] == "twentytwentyfour"
    assert body["data"][0]["name"] == "Twenty Twenty-Four"
    assert body["data"][0]["version"] == "1.0.0"
    assert body["data"][0]["is_present"] is True


async def test_list_plugins_returns_empty_when_none_seeded(
    client: TestClient, api_key: str
) -> None:
    response = client.get(
        "/api/v1/inventory/plugins", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert response.status_code == 200
    assert response.json()["data"] == []
