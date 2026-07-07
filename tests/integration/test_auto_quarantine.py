from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from sentinel.application.integrity.use_cases import (
    AutoQuarantineCriticalFindingsUseCase,
    QuarantineFindingUseCase,
)
from sentinel.config import Settings
from sentinel.domain.integrity.value_objects import RemediationState
from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.models.discovery import CpanelAccountModel, ServerModel
from sentinel.infrastructure.persistence.models.integrity import IntegrityFindingModel
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
)
from sentinel.infrastructure.persistence.repositories.events import SqlAlchemyEventRepository
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
    SqlAlchemyRemediationActionRepository,
)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Overrides the conftest ``settings`` fixture with a real, isolated
    quarantine directory and ``mode="active"`` — the one thing that makes
    ``AutoQuarantineCriticalFindingsUseCase`` actually act."""
    db_path = tmp_path / "test.db"
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_path}",
        quarantine_root_directory=str(tmp_path / "quarantine"),
        mode="active",
    )


async def _seed_account_and_critical_finding(database: Database, *, home: Path) -> str:
    now = utcnow()
    async with database.session() as session:
        server = ServerModel(
            id=uuid.uuid4(),
            hostname="host.example.com",
            os_info="Linux 6.1",
            agent_version="0.1.0",
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(server)
        await session.flush()

        account = CpanelAccountModel(
            id=uuid.uuid4(),
            server_id=server.id,
            username="examplebob",
            primary_domain="example.com",
            home_directory=str(home),
            is_suspended=False,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(account)
        await session.flush()

        finding = IntegrityFindingModel(
            id=uuid.uuid4(),
            account_id=account.id,
            relative_path="public_html/shell.php",
            change_type="ADDED",
            severity="CRITICAL",
            previous_sha256=None,
            current_sha256=None,
            is_acknowledged=False,
            remediation_state="NONE",
            detected_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(finding)
        await session.commit()
        return str(finding.id)


async def test_auto_quarantine_quarantines_critical_finding_end_to_end(
    database: Database, settings: Settings, tmp_path: Path
) -> None:
    """Exercises the real SQLite-backed ``list_critical_unremediated``
    query plus the real ``FilesystemFileRemediator`` against an actual file
    on disk — not fakes — confirming the whole wiring
    (job_registry.py's shape, reproduced here) behaves correctly end to
    end in ``active`` mode."""
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "shell.php"
    target.write_text("<?php system($_GET['c']); ?>")

    finding_id = await _seed_account_and_critical_finding(database, home=home)

    async with database.session() as session:
        finding_repository = SqlAlchemyIntegrityFindingRepository(session)
        quarantine_use_case = QuarantineFindingUseCase(
            finding_repository=finding_repository,
            account_repository=SqlAlchemyCpanelAccountRepository(session),
            baseline_repository=SqlAlchemyFileBaselineRepository(session),
            action_repository=SqlAlchemyRemediationActionRepository(session),
            remediator=FilesystemFileRemediator(
                quarantine_root_directory=settings.quarantine_root_directory
            ),
        )
        use_case = AutoQuarantineCriticalFindingsUseCase(
            finding_repository=finding_repository,
            event_repository=SqlAlchemyEventRepository(session),
            quarantine_use_case=quarantine_use_case,
            mode=settings.mode,
            max_per_account_per_run=settings.auto_quarantine_max_per_account_per_run,
            lookback_minutes=60,
        )
        result = await use_case.execute()
        await session.commit()

    assert result.findings_quarantined == 1
    assert result.circuit_breaker_trips == 0
    assert not target.exists()

    async with database.session() as session:
        finding = await SqlAlchemyIntegrityFindingRepository(session).get(uuid.UUID(finding_id))
    assert finding is not None
    assert finding.remediation_state == RemediationState.QUARANTINED
    assert finding.quarantine_path is not None
    assert Path(finding.quarantine_path).is_dir()


async def test_auto_quarantine_skips_in_manual_mode_end_to_end(
    database: Database, settings: Settings, tmp_path: Path
) -> None:
    home = tmp_path / "home" / "examplebob"
    (home / "public_html").mkdir(parents=True)
    target = home / "public_html" / "shell.php"
    target.write_text("<?php system($_GET['c']); ?>")

    finding_id = await _seed_account_and_critical_finding(database, home=home)

    async with database.session() as session:
        finding_repository = SqlAlchemyIntegrityFindingRepository(session)
        quarantine_use_case = QuarantineFindingUseCase(
            finding_repository=finding_repository,
            account_repository=SqlAlchemyCpanelAccountRepository(session),
            baseline_repository=SqlAlchemyFileBaselineRepository(session),
            action_repository=SqlAlchemyRemediationActionRepository(session),
            remediator=FilesystemFileRemediator(
                quarantine_root_directory=settings.quarantine_root_directory
            ),
        )
        use_case = AutoQuarantineCriticalFindingsUseCase(
            finding_repository=finding_repository,
            event_repository=SqlAlchemyEventRepository(session),
            quarantine_use_case=quarantine_use_case,
            mode="manual",
            max_per_account_per_run=5,
            lookback_minutes=60,
        )
        result = await use_case.execute()

    assert result.findings_quarantined == 0
    assert target.exists()

    async with database.session() as session:
        finding = await SqlAlchemyIntegrityFindingRepository(session).get(uuid.UUID(finding_id))
    assert finding is not None
    assert finding.remediation_state == RemediationState.NONE
