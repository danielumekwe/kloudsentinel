from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models.discovery import (
    CpanelAccountModel,
    ServerModel,
    WordPressInstallationModel,
)
from sentinel.infrastructure.persistence.models.events import SecurityEventModel
from sentinel.infrastructure.persistence.models.intelligence import (
    IncidentAccountLinkModel,
    IncidentModel,
)
from sentinel.infrastructure.persistence.models.inventory import (
    InstalledPluginModel,
    InstalledThemeModel,
)


async def _seed_account(database: Database, *, username: str) -> str:
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
        await session.commit()
        return str(account.id)


async def _seed_installation(
    database: Database,
    *,
    account_id: str,
    wp_version: str | None = "6.5",
    php_version: str | None = "8.1",
) -> str:
    now = utcnow()
    async with database.session() as session:
        installation = WordPressInstallationModel(
            id=uuid4(),
            cpanel_account_id=account_id,
            absolute_path=f"/home/x/public_html-{uuid4().hex}",
            domain="example.com",
            wp_version=wp_version,
            php_version=php_version,
            is_multisite=False,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(installation)
        await session.commit()
        return str(installation.id)


async def _seed_plugin(
    database: Database, *, installation_id: str, slug: str = "akismet", version: str = "5.1"
) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            InstalledPluginModel(
                id=uuid4(),
                installation_id=installation_id,
                slug=slug,
                name=slug.title(),
                version=version,
                is_present=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


async def _seed_theme(
    database: Database, *, installation_id: str, slug: str = "twentytwenty", version: str = "1.0"
) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            InstalledThemeModel(
                id=uuid4(),
                installation_id=installation_id,
                slug=slug,
                name=slug.title(),
                version=version,
                is_present=True,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


async def _seed_incident(database: Database, *, title: str = "Correlated activity") -> str:
    now = utcnow()
    async with database.session() as session:
        incident = IncidentModel(
            id=uuid4(),
            title=title,
            correlation_signature="wordpress_dropin_present",
            status="OPEN",
            severity="CRITICAL",
            confidence=0.9,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(incident)
        await session.commit()
        return str(incident.id)


async def _seed_link(database: Database, *, incident_id: str, account_id: str) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            IncidentAccountLinkModel(
                id=uuid4(),
                incident_id=incident_id,
                account_id=account_id,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


async def _seed_event(database: Database, *, account_id: str, sha256: str) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            SecurityEventModel(
                id=uuid4(),
                event_type="wordpress_dropin_present",
                source_context="wordpress",
                account_id=account_id,
                severity="CRITICAL",
                payload=json.dumps({}),
                occurred_at=now,
                sha256=sha256,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


def test_installation_inventory_requires_authentication(client: TestClient) -> None:
    response = client.get(f"/api/v1/wp/installations/{uuid4()}/inventory")
    assert response.status_code == 401


def test_installation_inventory_returns_404_for_unknown_installation(
    client: TestClient, api_key: str
) -> None:
    response = client.get(
        f"/api/v1/wp/installations/{uuid4()}/inventory",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 404


async def test_installation_inventory_returns_seeded_data(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    installation_id = await _seed_installation(database, account_id=account_id)

    response = client.get(
        f"/api/v1/wp/installations/{installation_id}/inventory",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["installation_id"] == installation_id
    assert body["wp_version"] == "6.5"
    assert body["php_version"] == "8.1"
    assert len(body["drop_ins"]) == 3
    assert all(not d["is_present"] for d in body["drop_ins"])
    assert body["must_use_plugins"] == []


def test_installation_integrity_requires_authentication(client: TestClient) -> None:
    response = client.get(f"/api/v1/wp/installations/{uuid4()}/integrity")
    assert response.status_code == 401


async def test_installation_integrity_reports_unknown_without_wp_version(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    installation_id = await _seed_installation(database, account_id=account_id, wp_version=None)

    response = client.get(
        f"/api/v1/wp/installations/{installation_id}/integrity",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert len(body) > 0
    assert all(item["status"] == "UNKNOWN" for item in body)


def test_incident_report_requires_authentication(client: TestClient) -> None:
    response = client.get(f"/api/v1/wp/incidents/{uuid4()}/report")
    assert response.status_code == 401


def test_incident_report_returns_404_for_unknown_incident(client: TestClient, api_key: str) -> None:
    response = client.get(
        f"/api/v1/wp/incidents/{uuid4()}/report",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 404


async def test_incident_report_surfaces_shared_plugins_themes_and_hashes(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_a = await _seed_account(database, username="accounta")
    account_b = await _seed_account(database, username="accountb")
    installation_a = await _seed_installation(database, account_id=account_a)
    installation_b = await _seed_installation(database, account_id=account_b)

    await _seed_plugin(database, installation_id=installation_a)
    await _seed_plugin(database, installation_id=installation_b)
    await _seed_theme(database, installation_id=installation_a)
    await _seed_theme(database, installation_id=installation_b)

    shared_hash = "a" * 64
    await _seed_event(database, account_id=account_a, sha256=shared_hash)
    await _seed_event(database, account_id=account_b, sha256=shared_hash)

    incident_id = await _seed_incident(database)
    await _seed_link(database, incident_id=incident_id, account_id=account_a)
    await _seed_link(database, incident_id=incident_id, account_id=account_b)

    response = client.get(
        f"/api/v1/wp/incidents/{incident_id}/report",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["incident_id"] == incident_id
    assert set(body["affected_account_ids"]) == {account_a, account_b}
    assert [a["identifier"] for a in body["shared_plugins"]] == ["akismet 5.1"]
    assert [a["identifier"] for a in body["shared_themes"]] == ["twentytwenty 1.0"]
    assert [a["identifier"] for a in body["shared_hashes"]] == [shared_hash]
