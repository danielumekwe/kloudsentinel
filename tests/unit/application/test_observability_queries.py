from __future__ import annotations

from uuid import UUID, uuid4

from sentinel.application.observability.queries import (
    GetDashboardSummaryQuery,
    GetSystemStatusQuery,
)
from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.forensics.entities import TempFileObservation
from sentinel.domain.forensics.value_objects import TempFileVerdict
from sentinel.domain.integrity.entities import IntegrityFinding
from sentinel.domain.integrity.value_objects import ChangeType, RemediationState
from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.observability.value_objects import JobHeartbeatStatus
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import (
    AbsoluteFilePath,
    DomainName,
    RelativeFilePath,
    Severity,
    Sha256Hash,
)

_HASH = "a" * 64


class FakeJobHeartbeatRepository:
    def __init__(self, heartbeats: list[JobHeartbeat] | None = None) -> None:
        self.by_id: dict[UUID, JobHeartbeat] = {h.id: h for h in heartbeats or []}

    async def add(self, entity: JobHeartbeat) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: JobHeartbeat) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> JobHeartbeat | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[JobHeartbeat]:
        return list(self.by_id.values())[offset : offset + limit]

    async def find_by_job_id(self, job_id: str) -> JobHeartbeat | None:
        return next((h for h in self.by_id.values() if h.job_id == job_id), None)


class FakeSecurityEventRepository:
    def __init__(self, events: list[SecurityEvent] | None = None) -> None:
        self.by_id: dict[UUID, SecurityEvent] = {e.id: e for e in events or []}

    async def add(self, entity: SecurityEvent) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: SecurityEvent) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> SecurityEvent | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[SecurityEvent]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_unprocessed(self, *, limit: int = 200) -> list[SecurityEvent]:
        return [e for e in self.by_id.values() if e.processed_at is None][:limit]

    async def count_total(self) -> int:
        return len(self.by_id)

    async def count_unprocessed(self) -> int:
        return len([e for e in self.by_id.values() if e.processed_at is None])


class FakeIntegrityFindingRepository:
    def __init__(self, findings: list[IntegrityFinding] | None = None) -> None:
        self.by_id: dict[UUID, IntegrityFinding] = {f.id: f for f in findings or []}

    async def add(self, entity: IntegrityFinding) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: IntegrityFinding) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> IntegrityFinding | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[IntegrityFinding]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_unacknowledged(
        self, *, limit: int = 50, offset: int = 0
    ) -> list[IntegrityFinding]:
        return [f for f in self.by_id.values() if not f.is_acknowledged][offset : offset + limit]

    async def count_total(self) -> int:
        return len(self.by_id)

    async def list_by_remediation_state(
        self, state: RemediationState, *, limit: int = 200
    ) -> list[IntegrityFinding]:
        return [f for f in self.by_id.values() if f.remediation_state == state][:limit]


class FakeCpanelAccountRepository:
    def __init__(self, accounts: list[CpanelAccount] | None = None) -> None:
        self.by_id: dict[UUID, CpanelAccount] = {a.id: a for a in accounts or []}

    async def add(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> CpanelAccount | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CpanelAccount]:
        return list(self.by_id.values())[offset : offset + limit]

    async def count_total(self) -> int:
        return len(self.by_id)


class FakeTempFileObservationRepository:
    def __init__(self, observations: list[TempFileObservation] | None = None) -> None:
        self.by_id: dict[UUID, TempFileObservation] = {o.id: o for o in observations or []}

    async def add(self, entity: TempFileObservation) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: TempFileObservation) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> TempFileObservation | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[TempFileObservation]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> TempFileObservation | None:
        return next((o for o in self.by_id.values() if str(o.absolute_path) == absolute_path), None)

    async def count_by_verdict(self, verdict: TempFileVerdict) -> int:
        return len([o for o in self.by_id.values() if o.verdict == verdict])


def _finding() -> IntegrityFinding:
    return IntegrityFinding(
        account_id=uuid4(),
        relative_path=RelativeFilePath(value="public_html/shell.php"),
        change_type=ChangeType.ADDED,
        severity=Severity.MEDIUM,
        previous_sha256=None,
        current_sha256=Sha256Hash(value=_HASH),
        detected_at=utcnow(),
    )


def _observation(verdict: TempFileVerdict) -> TempFileObservation:
    return TempFileObservation(
        absolute_path=AbsoluteFilePath(value=f"/tmp/{uuid4().hex}.php"),
        sha256=Sha256Hash(value=_HASH),
        owner="bob",
        size_bytes=10,
        verdict=verdict,
        verdict_reason="test",
        matched_rule_ids=(),
        process=None,
        account_id=None,
        detected_at=utcnow(),
    )


def _account() -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value="/home/examplebob"),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _event(*, processed: bool) -> SecurityEvent:
    return SecurityEvent(
        event_type="temp_file_malicious",
        source_context="forensics",
        account_id=None,
        severity=Severity.CRITICAL,
        payload={},
        occurred_at=utcnow(),
        processed_at=utcnow() if processed else None,
    )


async def test_get_system_status_aggregates_all_counters() -> None:
    heartbeats = FakeJobHeartbeatRepository(
        [
            JobHeartbeat(
                job_id="discovery",
                status=JobHeartbeatStatus.SUCCESS,
                last_run_at=utcnow(),
                last_duration_ms=1.0,
            )
        ]
    )
    events = FakeSecurityEventRepository([_event(processed=True), _event(processed=False)])
    findings = FakeIntegrityFindingRepository([_finding()])
    observations = FakeTempFileObservationRepository(
        [
            _observation(TempFileVerdict.MALICIOUS),
            _observation(TempFileVerdict.MALICIOUS),
            _observation(TempFileVerdict.SUSPICIOUS),
            _observation(TempFileVerdict.LEGITIMATE),
        ]
    )

    query = GetSystemStatusQuery(
        heartbeat_repository=heartbeats,
        event_repository=events,
        finding_repository=findings,
        observation_repository=observations,
    )

    result = await query.execute()

    assert len(result.heartbeats) == 1
    assert result.heartbeats[0].job_id == "discovery"
    assert result.events_total == 2
    assert result.events_unprocessed == 1
    assert result.integrity_findings_total == 1
    assert result.temp_files_malicious == 2
    assert result.temp_files_suspicious == 1


async def test_get_system_status_handles_empty_repositories() -> None:
    query = GetSystemStatusQuery(
        heartbeat_repository=FakeJobHeartbeatRepository(),
        event_repository=FakeSecurityEventRepository(),
        finding_repository=FakeIntegrityFindingRepository(),
        observation_repository=FakeTempFileObservationRepository(),
    )

    result = await query.execute()

    assert result.heartbeats == []
    assert result.events_total == 0
    assert result.events_unprocessed == 0
    assert result.integrity_findings_total == 0
    assert result.temp_files_malicious == 0
    assert result.temp_files_suspicious == 0


async def test_get_dashboard_summary_composes_system_status_with_accounts_and_events() -> None:
    findings = FakeIntegrityFindingRepository([_finding()])
    quarantined = _finding()
    quarantined.quarantine(
        quarantine_path="/var/lib/sentinel/quarantine/x",
        mode="600",
        size_bytes=10,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )
    findings.by_id[quarantined.id] = quarantined
    accounts = FakeCpanelAccountRepository([_account(), _account()])
    events = FakeSecurityEventRepository([_event(processed=True), _event(processed=False)])

    query = GetDashboardSummaryQuery(
        system_status_query=GetSystemStatusQuery(
            heartbeat_repository=FakeJobHeartbeatRepository(),
            event_repository=events,
            finding_repository=findings,
            observation_repository=FakeTempFileObservationRepository(),
        ),
        account_repository=accounts,
        event_repository=events,
        finding_repository=findings,
    )

    result = await query.execute()

    assert result.protected_accounts_total == 2
    assert result.threats_detected_total == len(findings.by_id)
    assert result.quarantined_files_total == 1
    assert len(result.recent_events) == 2
    assert result.heartbeats == []
