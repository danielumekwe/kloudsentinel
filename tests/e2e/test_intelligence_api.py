from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models.discovery import CpanelAccountModel, ServerModel
from sentinel.infrastructure.persistence.models.events import SecurityEventModel
from sentinel.infrastructure.persistence.models.intelligence import (
    IncidentAccountLinkModel,
    IncidentModel,
    ThreatTimelineEntryModel,
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


async def _seed_event(
    database: Database, *, account_id: str | None = None, event_type: str = "temp_file_malicious"
) -> str:
    now = utcnow()
    async with database.session() as session:
        event = SecurityEventModel(
            id=uuid4(),
            event_type=event_type,
            source_context="forensics",
            account_id=account_id,
            severity="CRITICAL",
            payload=json.dumps({"absolute_path": "/tmp/update_abc.php"}),
            occurred_at=now,
            processed_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(event)
        await session.commit()
        return str(event.id)


async def _seed_incident(
    database: Database,
    *,
    title: str = "Correlated temp_file_malicious activity",
    status: str = "OPEN",
    confidence: float = 0.9,
) -> str:
    now = utcnow()
    async with database.session() as session:
        incident = IncidentModel(
            id=uuid4(),
            title=title,
            correlation_signature="temp_file_malicious:webshell-signature",
            status=status,
            severity="CRITICAL",
            confidence=confidence,
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


async def _seed_timeline_entry(
    database: Database, *, incident_id: str, source_event_id: str | None = None
) -> str:
    now = utcnow()
    async with database.session() as session:
        entry = ThreatTimelineEntryModel(
            id=uuid4(),
            incident_id=incident_id,
            stage="TEMP_FILE_MALICIOUS",
            description="/tmp/update_abc.php",
            occurred_at=now,
            source_event_id=source_event_id,
            created_at=now,
            updated_at=now,
        )
        session.add(entry)
        await session.commit()
        return str(entry.id)


def test_list_incidents_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/incidents")
    assert response.status_code == 401


async def test_list_incidents_returns_seeded_incident(
    client: TestClient, database: Database, api_key: str
) -> None:
    await _seed_incident(database)

    response = client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {api_key}"})

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["status"] == "OPEN"
    assert body["data"][0]["confidence"] == 0.9


async def test_get_incident_returns_full_detail(
    client: TestClient, database: Database, api_key: str
) -> None:
    incident_id = await _seed_incident(database, title="Correlated webshell activity")

    response = client.get(
        f"/api/v1/incidents/{incident_id}", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["id"] == incident_id
    assert body["title"] == "Correlated webshell activity"


async def test_get_unknown_incident_returns_404(client: TestClient, api_key: str) -> None:
    response = client.get(
        f"/api/v1/incidents/{uuid4()}", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 404


async def test_incident_timeline_returns_ordered_entries(
    client: TestClient, database: Database, api_key: str
) -> None:
    incident_id = await _seed_incident(database)
    event_id = await _seed_event(database)
    await _seed_timeline_entry(database, incident_id=incident_id, source_event_id=event_id)

    response = client.get(
        f"/api/v1/incidents/{incident_id}/timeline",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert len(body) == 1
    assert body[0]["stage"] == "TEMP_FILE_MALICIOUS"
    assert body[0]["source_event_id"] == event_id


async def test_incident_evidence_returns_linked_security_events(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    incident_id = await _seed_incident(database)
    event_id = await _seed_event(database, account_id=account_id)
    await _seed_link(database, incident_id=incident_id, account_id=account_id)
    await _seed_timeline_entry(database, incident_id=incident_id, source_event_id=event_id)

    response = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert len(body) == 1
    assert body[0]["id"] == event_id
    assert body[0]["payload"]["absolute_path"] == "/tmp/update_abc.php"


async def test_incident_evidence_empty_when_timeline_has_no_source_events(
    client: TestClient, database: Database, api_key: str
) -> None:
    incident_id = await _seed_incident(database)
    await _seed_timeline_entry(database, incident_id=incident_id, source_event_id=None)

    response = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    assert response.json()["data"] == []
