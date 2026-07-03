from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models.discovery import CpanelAccountModel, ServerModel
from sentinel.infrastructure.persistence.models.integrity import (
    FileBaselineModel,
    IntegrityFindingModel,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64


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


async def _seed_baseline(database: Database, *, account_id: str) -> None:
    now = utcnow()
    async with database.session() as session:
        session.add(
            FileBaselineModel(
                id=uuid4(),
                account_id=account_id,
                relative_path="public_html/index.php",
                sha256=_HASH_A,
                size_bytes=100,
                mode="644",
                is_active=True,
                last_verified_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


async def _seed_finding(database: Database, *, account_id: str) -> str:
    now = utcnow()
    async with database.session() as session:
        finding = IntegrityFindingModel(
            id=uuid4(),
            account_id=account_id,
            relative_path="public_html/index.php",
            change_type="MODIFIED",
            severity="HIGH",
            previous_sha256=_HASH_A,
            current_sha256=_HASH_B,
            is_acknowledged=False,
            detected_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(finding)
        await session.commit()
        return str(finding.id)


def test_list_baselines_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/integrity/baselines")
    assert response.status_code == 401


async def test_list_baselines_returns_seeded_baseline(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    await _seed_baseline(database, account_id=account_id)

    response = client.get(
        "/api/v1/integrity/baselines", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["relative_path"] == "public_html/index.php"
    assert body["data"][0]["sha256"] == _HASH_A


def test_list_findings_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/integrity/findings")
    assert response.status_code == 401


async def test_list_findings_returns_seeded_finding(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    await _seed_finding(database, account_id=account_id)

    response = client.get(
        "/api/v1/integrity/findings", headers={"Authorization": f"Bearer {api_key}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["change_type"] == "MODIFIED"
    assert body["data"][0]["severity"] == "HIGH"
    assert body["data"][0]["is_acknowledged"] is False


async def test_list_findings_unacknowledged_only_filter(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    client.post(
        f"/api/v1/integrity/findings/{finding_id}/acknowledge",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    response = client.get(
        "/api/v1/integrity/findings",
        params={"unacknowledged_only": True},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    assert response.json()["data"] == []


async def test_acknowledge_finding_marks_it_acknowledged(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/acknowledge",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["is_acknowledged"] is True


async def test_acknowledge_unknown_finding_returns_404(client: TestClient, api_key: str) -> None:
    response = client.post(
        f"/api/v1/integrity/findings/{uuid4()}/acknowledge",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 404
