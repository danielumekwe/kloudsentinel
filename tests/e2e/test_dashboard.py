from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from sentinel.application.integrity.use_cases import QuarantineFindingUseCase
from sentinel.config import Settings
from sentinel.domain.integrity.value_objects import RemediationState
from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models import AdminUserModel
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
)
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
    SqlAlchemyRemediationActionRepository,
)
from sentinel.infrastructure.security.passwords import hash_password
from tests.e2e.test_integrity_api import _seed_account, _seed_finding

_USERNAME = "admin"
_PASSWORD = "correct horse battery staple"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Overrides the conftest ``settings`` fixture — dashboard mutation
    tests (restore/delete) need a real, isolated quarantine directory and
    ``mode="manual"`` (mutation endpoints are blocked under the conftest
    default of ``observe``), same pattern as ``tests/e2e/test_integrity_api.py``."""
    db_path = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        log_level="DEBUG",
        quarantine_root_directory=str(tmp_path / "quarantine"),
        mode="manual",
    )


@pytest.fixture
async def admin_user(database: Database) -> str:
    """Inserts an active admin login and returns the username — every test
    in this file logs in with the module-level ``_PASSWORD`` constant."""
    async with database.session() as session:
        session.add(
            AdminUserModel(
                username=_USERNAME,
                password_hash=hash_password(_PASSWORD),
                is_active=True,
                created_at=utcnow(),
            )
        )
        await session.commit()
    return _USERNAME


def _login(client: TestClient, *, password: str = _PASSWORD) -> None:
    response = client.post(
        "/dashboard/login",
        data={"username": _USERNAME, "password": password},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _csrf_token(client: TestClient, path: str) -> str:
    html = client.get(path).text
    marker = 'name="csrf_token" value="'
    start = html.index(marker) + len(marker)
    return html[start : html.index('"', start)]


def test_unauthenticated_dashboard_redirects_to_login(client: TestClient) -> None:
    response = client.get("/dashboard/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/login"


def test_login_with_nonexistent_username_returns_generic_error(client: TestClient) -> None:
    """No `admin_user` fixture here — the username genuinely doesn't
    exist. Must behave identically to a wrong password for a real user
    (same status, same generic message) rather than a distinguishable
    error, and must still invoke bcrypt against a dummy hash rather than
    short-circuiting — see infrastructure/security/passwords.py's
    DUMMY_PASSWORD_HASH for why a fast-path here would let an attacker
    enumerate valid usernames via response timing."""
    response = client.post(
        "/dashboard/login", data={"username": "nonexistent", "password": "whatever"}
    )

    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert "sentinel_session" not in client.cookies


def test_login_with_wrong_password_shows_error_and_no_cookie(
    client: TestClient, admin_user: str
) -> None:
    response = client.post("/dashboard/login", data={"username": admin_user, "password": "wrong"})

    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert "sentinel_session" not in client.cookies


def test_login_with_correct_password_sets_cookie_and_redirects(
    client: TestClient, admin_user: str
) -> None:
    response = client.post(
        "/dashboard/login",
        data={"username": admin_user, "password": _PASSWORD},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert "sentinel_session" in client.cookies


def test_dashboard_renders_summary_after_login(client: TestClient, admin_user: str) -> None:
    _login(client)

    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "Protected accounts" in response.text
    assert "Run Scan Now" in response.text


async def test_quarantine_restore_requires_valid_csrf_token(
    client: TestClient, database: Database, admin_user: str
) -> None:
    _login(client)
    account_id = await _seed_account(database, username="examplebob")
    finding_id = await _seed_finding(database, account_id=account_id)

    response = client.post(
        f"/dashboard/quarantine/{finding_id}/restore", data={"csrf_token": "wrong"}
    )

    assert response.status_code == 403


async def test_quarantine_restore_end_to_end(
    client: TestClient, database: Database, settings: Settings, admin_user: str, tmp_path: Path
) -> None:
    """Seeds a real quarantined finding the same way the JSON API and CLI
    do (via `QuarantineFindingUseCase` against a real file on disk), then
    exercises the dashboard's restore action end to end — same pattern as
    `tests/integration/test_auto_quarantine.py`."""
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "index.php"
    target.write_text("<?php echo 'hi'; ?>")

    account_id = await _seed_account(database, username="examplebob", home_directory=str(home))
    finding_id = await _seed_finding(database, account_id=account_id)

    async with database.session() as session:
        use_case = QuarantineFindingUseCase(
            finding_repository=SqlAlchemyIntegrityFindingRepository(session),
            account_repository=SqlAlchemyCpanelAccountRepository(session),
            baseline_repository=SqlAlchemyFileBaselineRepository(session),
            action_repository=SqlAlchemyRemediationActionRepository(session),
            remediator=FilesystemFileRemediator(
                quarantine_root_directory=settings.quarantine_root_directory
            ),
        )
        await use_case.execute(UUID(finding_id))
        await session.commit()
    assert not target.exists()

    _login(client)
    csrf = _csrf_token(client, "/dashboard/quarantine")
    response = client.post(
        f"/dashboard/quarantine/{finding_id}/restore",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/quarantine"
    assert target.exists()

    async with database.session() as session:
        restored = await SqlAlchemyIntegrityFindingRepository(session).get(UUID(finding_id))
        assert restored is not None
        assert restored.remediation_state is RemediationState.RESTORED


def test_run_scan_requires_valid_csrf_token(client: TestClient, admin_user: str) -> None:
    _login(client)

    response = client.post("/dashboard/scans/run", data={"csrf_token": "wrong"})

    assert response.status_code == 403


def test_run_scan_with_valid_csrf_redirects_to_dashboard(
    client: TestClient, admin_user: str
) -> None:
    _login(client)
    csrf = _csrf_token(client, "/dashboard")

    response = client.post(
        "/dashboard/scans/run", data={"csrf_token": csrf}, follow_redirects=False
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_logout_revokes_session(client: TestClient, admin_user: str) -> None:
    _login(client)
    csrf = _csrf_token(client, "/dashboard")

    logout_response = client.post(
        "/dashboard/logout", data={"csrf_token": csrf}, follow_redirects=False
    )
    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/dashboard/login"

    dashboard_response = client.get("/dashboard/", follow_redirects=False)
    assert dashboard_response.status_code == 303
    assert dashboard_response.headers["location"] == "/dashboard/login"
