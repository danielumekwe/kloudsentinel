from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from sentinel.config import Settings
from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models.discovery import CpanelAccountModel, ServerModel
from sentinel.infrastructure.persistence.models.integrity import (
    FileBaselineModel,
    IntegrityFindingModel,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Overrides the conftest ``settings`` fixture (picked up automatically
    by every other fixture in this file that depends on it, e.g. ``client``)
    so remediation tests get a real, isolated quarantine directory instead
    of the production default ``/var/sentinel/quarantine``."""
    db_path = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        log_level="DEBUG",
        quarantine_root_directory=str(tmp_path / "quarantine"),
    )


async def _seed_account(
    database: Database, *, username: str, home_directory: str | None = None
) -> str:
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
            home_directory=home_directory or f"/home/{username}",
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


async def _seed_finding(
    database: Database,
    *,
    account_id: str,
    relative_path: str = "public_html/index.php",
    change_type: str = "MODIFIED",
) -> str:
    now = utcnow()
    async with database.session() as session:
        finding = IntegrityFindingModel(
            id=uuid4(),
            account_id=account_id,
            relative_path=relative_path,
            change_type=change_type,
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


def test_quarantine_finding_requires_authentication(client: TestClient) -> None:
    response = client.post(f"/api/v1/integrity/findings/{uuid4()}/quarantine")
    assert response.status_code == 401


async def test_quarantine_finding_moves_file_out_of_account_home(
    client: TestClient, database: Database, api_key: str, tmp_path: Path
) -> None:
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    suspicious_file = home / "public_html" / "shell.php"
    suspicious_file.write_text("<?php system($_GET['c']); ?>")

    account_id = await _seed_account(database, username="examplebob", home_directory=str(home))
    finding_id = await _seed_finding(
        database, account_id=account_id, relative_path="public_html/shell.php", change_type="ADDED"
    )

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/quarantine",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["remediation_state"] == "QUARANTINED"
    assert body["quarantine_path"] is not None
    assert not suspicious_file.exists()
    assert Path(body["quarantine_path"]).is_file()


async def test_quarantine_deleted_finding_returns_409(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(
        database, account_id=account_id, relative_path="public_html/gone.php", change_type="DELETED"
    )

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/quarantine",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 409


async def test_quarantine_unknown_finding_returns_404(client: TestClient, api_key: str) -> None:
    response = client.post(
        f"/api/v1/integrity/findings/{uuid4()}/quarantine",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 404


async def test_restore_finding_puts_file_back_at_original_path(
    client: TestClient, database: Database, api_key: str, tmp_path: Path
) -> None:
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    suspicious_file = home / "public_html" / "shell.php"
    suspicious_file.write_text("<?php system($_GET['c']); ?>")

    account_id = await _seed_account(database, username="examplebob", home_directory=str(home))
    finding_id = await _seed_finding(
        database, account_id=account_id, relative_path="public_html/shell.php", change_type="ADDED"
    )

    headers = {"Authorization": f"Bearer {api_key}"}
    client.post(f"/api/v1/integrity/findings/{finding_id}/quarantine", headers=headers)

    response = client.post(f"/api/v1/integrity/findings/{finding_id}/restore", headers=headers)

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["remediation_state"] == "RESTORED"
    assert body["quarantine_path"] is None
    assert suspicious_file.is_file()


async def test_restore_without_prior_quarantine_returns_409(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/restore",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 409


async def test_delete_purges_quarantined_file(
    client: TestClient, database: Database, api_key: str, tmp_path: Path
) -> None:
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    suspicious_file = home / "public_html" / "shell.php"
    suspicious_file.write_text("<?php system($_GET['c']); ?>")

    account_id = await _seed_account(database, username="examplebob", home_directory=str(home))
    finding_id = await _seed_finding(
        database, account_id=account_id, relative_path="public_html/shell.php", change_type="ADDED"
    )

    headers = {"Authorization": f"Bearer {api_key}"}
    quarantine_response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/quarantine", headers=headers
    )
    quarantine_path = Path(quarantine_response.json()["data"]["quarantine_path"])

    response = client.post(f"/api/v1/integrity/findings/{finding_id}/delete", headers=headers)

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["remediation_state"] == "DELETED"
    assert not suspicious_file.exists()
    assert not quarantine_path.exists()

    second_delete = client.post(f"/api/v1/integrity/findings/{finding_id}/delete", headers=headers)
    assert second_delete.status_code == 409


async def test_delete_without_prior_quarantine_returns_409(
    client: TestClient, database: Database, api_key: str
) -> None:
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/api/v1/integrity/findings/{finding_id}/delete",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 409


async def test_list_remediation_actions_returns_audit_trail(
    client: TestClient, database: Database, api_key: str, tmp_path: Path
) -> None:
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    (home / "public_html" / "shell.php").write_text("<?php system($_GET['c']); ?>")

    account_id = await _seed_account(database, username="examplebob", home_directory=str(home))
    finding_id = await _seed_finding(
        database, account_id=account_id, relative_path="public_html/shell.php", change_type="ADDED"
    )

    headers = {"Authorization": f"Bearer {api_key}"}
    client.post(f"/api/v1/integrity/findings/{finding_id}/quarantine", headers=headers)
    client.post(f"/api/v1/integrity/findings/{finding_id}/restore", headers=headers)

    response = client.get(
        f"/api/v1/integrity/findings/{finding_id}/remediation-actions", headers=headers
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert len(body) == 2
    assert {action["action_type"] for action in body} == {"QUARANTINE", "RESTORE"}
    assert all(action["outcome"] == "SUCCEEDED" for action in body)
