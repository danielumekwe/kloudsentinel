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
from sentinel.infrastructure.persistence.models.monitoring import ConfigurationItemModel


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


async def _seed_config_item(
    database: Database,
    *,
    installation_id: str,
    key: str = "WP_DEBUG",
    is_flagged: bool = True,
) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            ConfigurationItemModel(
                id=uuid4(),
                installation_id=installation_id,
                config_source="wp-config.php",
                key=key,
                raw_value="true",
                is_flagged=is_flagged,
                flag_reason="Debug mode is enabled" if is_flagged else None,
                is_present=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


def test_list_configuration_items_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/configuration/items")
    assert response.status_code == 401


async def test_list_configuration_items_returns_seeded_item(
    client: TestClient, database: Database, api_key: str
) -> None:
    installation_id = await _seed_installation(database, username="configbob")
    await _seed_config_item(database, installation_id=installation_id)

    response = client.get(
        "/api/v1/configuration/items", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    item = body["data"][0]
    assert item["key"] == "WP_DEBUG"
    assert item["config_source"] == "wp-config.php"
    assert item["raw_value"] == "true"
    assert item["is_flagged"] is True
    assert item["flag_reason"] == "Debug mode is enabled"


async def test_list_configuration_items_returns_empty_when_none_seeded(
    client: TestClient, api_key: str
) -> None:
    response = client.get(
        "/api/v1/configuration/items", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert response.status_code == 200
    assert response.json()["data"] == []


async def test_list_configuration_items_returns_multiple_items(
    client: TestClient, database: Database, api_key: str
) -> None:
    installation_id = await _seed_installation(database, username="configmulti")
    await _seed_config_item(database, installation_id=installation_id, key="WP_DEBUG")
    await _seed_config_item(
        database, installation_id=installation_id, key="DISALLOW_FILE_EDIT", is_flagged=False
    )

    response = client.get(
        "/api/v1/configuration/items", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    assert len(response.json()["data"]) == 2
