from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest

from sentinel.application.integrity.use_cases import (
    AutoQuarantineCriticalFindingsUseCase,
    DeleteFindingUseCase,
    QuarantineFindingUseCase,
    RestoreFindingUseCase,
    RunIntegrityScanUseCase,
)
from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding, RemediationAction
from sentinel.domain.integrity.value_objects import (
    ChangeType,
    QuarantinedFile,
    RemediationActionType,
    RemediationOutcome,
    RemediationState,
    ScannedFile,
)
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import (
    EntityNotFoundError,
    FileRemediationError,
    InvariantViolationError,
)
from sentinel.domain.shared.value_objects import (
    AbsoluteFilePath,
    DomainName,
    RelativeFilePath,
    Severity,
    Sha256Hash,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64


class FakeCpanelAccountRepository:
    def __init__(self, accounts: list[CpanelAccount]) -> None:
        self.by_id: dict[UUID, CpanelAccount] = {a.id: a for a in accounts}

    async def add(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: CpanelAccount) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> CpanelAccount | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CpanelAccount]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_username(self, username: LinuxUsername) -> CpanelAccount | None:
        return next((a for a in self.by_id.values() if a.username == username), None)

    async def list_by_server(self, server_id: UUID) -> list[CpanelAccount]:
        return [a for a in self.by_id.values() if a.server_id == server_id]


class FakeFileBaselineRepository:
    def __init__(self, baselines: list[FileBaseline] | None = None) -> None:
        self.by_id: dict[UUID, FileBaseline] = {b.id: b for b in baselines or []}

    async def add(self, entity: FileBaseline) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: FileBaseline) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> FileBaseline | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[FileBaseline]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_account_and_path(
        self, account_id: UUID, relative_path: RelativeFilePath
    ) -> FileBaseline | None:
        return next(
            (
                b
                for b in self.by_id.values()
                if b.account_id == account_id and b.relative_path == relative_path
            ),
            None,
        )

    async def list_by_account(self, account_id: UUID) -> list[FileBaseline]:
        return [b for b in self.by_id.values() if b.account_id == account_id]


class FakeIntegrityFindingRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, IntegrityFinding] = {}

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

    async def list_since(self, since: datetime, *, limit: int = 500) -> list[IntegrityFinding]:
        return [f for f in self.by_id.values() if f.detected_at >= since][:limit]

    async def list_by_remediation_state(
        self, state: RemediationState, *, limit: int = 200
    ) -> list[IntegrityFinding]:
        return [f for f in self.by_id.values() if f.remediation_state == state][:limit]

    async def list_critical_unremediated(
        self, since: datetime, *, limit: int = 500
    ) -> list[IntegrityFinding]:
        matching = [
            f
            for f in self.by_id.values()
            if f.severity is Severity.CRITICAL
            and f.remediation_state is RemediationState.NONE
            and f.detected_at >= since
        ]
        return sorted(matching, key=lambda f: f.detected_at)[:limit]


class FakeSecurityEventRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, SecurityEvent] = {}

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


class FakeFileScanner:
    def __init__(self, by_account_id: dict[UUID, list[ScannedFile]]) -> None:
        self._by_account_id = by_account_id

    async def scan(self, account: CpanelAccount) -> list[ScannedFile]:
        return self._by_account_id.get(account.id, [])


class FakeRemediationActionRepository:
    def __init__(self) -> None:
        self.by_id: dict[UUID, RemediationAction] = {}

    async def add(self, entity: RemediationAction) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: RemediationAction) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> RemediationAction | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[RemediationAction]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_by_finding(self, finding_id: UUID) -> list[RemediationAction]:
        return [a for a in self.by_id.values() if a.finding_id == finding_id]


class FakeFileRemediator:
    """Simulates the filesystem side of remediation. Set ``fail=True`` to
    make every operation raise ``FileRemediationError``, mimicking a disk
    failure, so use cases' failure-path handling can be exercised without a
    real filesystem."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.purge_calls: list[str] = []

    async def quarantine(
        self,
        *,
        account: CpanelAccount,
        relative_path: RelativeFilePath,
        detection_reason: str,
        severity: Severity,
        detected_at: datetime,
    ) -> QuarantinedFile:
        if self.fail:
            raise FileRemediationError("simulated quarantine failure")
        return QuarantinedFile(
            quarantine_path=f"/var/lib/sentinel/quarantine/{account.username}/{relative_path}",
            mode="644",
            size_bytes=100,
            owner_uid=1000,
            owner_gid=1000,
        )

    async def restore(
        self,
        *,
        account: CpanelAccount,
        relative_path: RelativeFilePath,
        quarantine_path: str,
        mode: str,
        owner_uid: int | None,
        owner_gid: int | None,
    ) -> None:
        if self.fail:
            raise FileRemediationError("simulated restore failure")

    async def purge(self, *, quarantine_path: str) -> None:
        if self.fail:
            raise FileRemediationError("simulated purge failure")
        self.purge_calls.append(quarantine_path)


def _account(*, is_active: bool = True) -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob1"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value="/home/examplebob1"),
        is_suspended=False,
        is_active=is_active,
        last_seen_at=utcnow(),
    )


def _scanned_file(
    path: str, sha256: str, *, size_bytes: int = 100, mode: str = "644"
) -> ScannedFile:
    return ScannedFile(
        relative_path=RelativeFilePath(value=path),
        sha256=Sha256Hash(value=sha256),
        size_bytes=size_bytes,
        mode=mode,
    )


def _finding(
    account_id: UUID,
    *,
    change_type: ChangeType = ChangeType.ADDED,
    severity: Severity = Severity.MEDIUM,
    relative_path: str = "public_html/shell.php",
    detected_at: datetime | None = None,
) -> IntegrityFinding:
    return IntegrityFinding(
        account_id=account_id,
        relative_path=RelativeFilePath(value=relative_path),
        change_type=change_type,
        severity=severity,
        previous_sha256=None,
        current_sha256=Sha256Hash(value=_HASH_B),
        detected_at=detected_at or utcnow(),
    )


async def test_first_scan_establishes_baselines_without_findings() -> None:
    account = _account()
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository()
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_A)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.accounts_scanned == 1
    assert result.baselines_established == 1
    assert result.findings_created == 0
    assert len(baselines.by_id) == 1
    assert len(findings.by_id) == 0


async def test_unchanged_file_is_a_no_op() -> None:
    account = _account()
    existing = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="public_html/index.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository([existing])
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_A)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.findings_created == 0
    assert result.baselines_established == 0
    assert result.baselines_removed == 0


async def test_modified_file_creates_high_severity_finding() -> None:
    account = _account()
    existing = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="public_html/index.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository([existing])
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_B)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.findings_created == 1
    (finding,) = findings.by_id.values()
    assert finding.change_type == ChangeType.MODIFIED
    assert finding.severity == Severity.HIGH
    assert str(finding.previous_sha256) == _HASH_A
    assert str(finding.current_sha256) == _HASH_B
    (baseline,) = baselines.by_id.values()
    assert str(baseline.sha256) == _HASH_B

    (event,) = events.by_id.values()
    assert event.event_type == "integrity_finding_modified"
    assert event.source_context == "integrity"
    assert event.account_id == account.id
    assert event.severity == Severity.HIGH
    assert event.payload["finding_id"] == str(finding.id)
    assert event.server_id == account.server_id
    assert event.file_path == "public_html/index.php"
    assert event.sha256 == _HASH_B
    assert event.file_size_bytes == 100
    assert event.file_owner == str(account.username)
    assert event.file_permissions == "644"
    # `.php` has no registered MIME type in Python's stdlib `mimetypes` table.
    assert event.mime_type is None
    assert event.scanner_version == "integrity-hash-diff@1"
    assert event.detection_rule_id == "MODIFIED"


async def test_new_file_on_already_baselined_account_creates_medium_added_finding() -> None:
    account = _account()
    existing = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="public_html/index.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository([existing])
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner(
        {
            account.id: [
                _scanned_file("public_html/index.php", _HASH_A),
                _scanned_file("public_html/shell.php", _HASH_B),
            ]
        }
    )

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.findings_created == 1
    assert result.baselines_established == 1
    (finding,) = findings.by_id.values()
    assert finding.change_type == ChangeType.ADDED
    assert finding.severity == Severity.MEDIUM
    assert finding.previous_sha256 is None


async def test_removed_file_creates_high_deleted_finding_and_deactivates_baseline() -> None:
    account = _account()
    existing = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="public_html/index.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository([existing])
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner({account.id: []})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.findings_created == 1
    assert result.baselines_removed == 1
    (finding,) = findings.by_id.values()
    assert finding.change_type == ChangeType.DELETED
    assert finding.severity == Severity.HIGH
    assert finding.current_sha256 is None
    (baseline,) = baselines.by_id.values()
    assert baseline.is_active is False


async def test_permission_only_change_creates_medium_finding() -> None:
    account = _account()
    existing = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="public_html/wp-config.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository([existing])
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner(
        {account.id: [_scanned_file("public_html/wp-config.php", _HASH_A, mode="666")]}
    )

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.findings_created == 1
    (finding,) = findings.by_id.values()
    assert finding.change_type == ChangeType.PERMISSIONS_CHANGED
    assert finding.severity == Severity.MEDIUM
    (baseline,) = baselines.by_id.values()
    assert baseline.mode == "666"


async def test_inactive_accounts_are_skipped() -> None:
    account = _account(is_active=False)
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository()
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_A)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    result = await use_case.execute()

    assert result.accounts_scanned == 0
    assert len(baselines.by_id) == 0


async def test_reappeared_file_reactivates_baseline_instead_of_duplicating() -> None:
    account = _account()
    removed = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="public_html/index.php"),
        sha256=Sha256Hash(value=_HASH_A),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
        is_active=False,
    )
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository([removed])
    findings = FakeIntegrityFindingRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_B)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        event_repository=events,
        scanner=scanner,
    )

    await use_case.execute()

    assert len(baselines.by_id) == 1
    (baseline,) = baselines.by_id.values()
    assert baseline.is_active is True
    assert str(baseline.sha256) == _HASH_B
    (finding,) = findings.by_id.values()
    assert finding.change_type == ChangeType.ADDED


async def test_quarantine_use_case_moves_file_and_deactivates_baseline() -> None:
    account = _account()
    finding = _finding(account.id)
    baseline = FileBaseline(
        account_id=account.id,
        relative_path=finding.relative_path,
        sha256=Sha256Hash(value=_HASH_B),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    baselines = FakeFileBaselineRepository([baseline])
    actions = FakeRemediationActionRepository()

    use_case = QuarantineFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=baselines,
        action_repository=actions,
        remediator=FakeFileRemediator(),
    )

    result = await use_case.execute(finding.id)

    assert result.remediation_state == RemediationState.QUARANTINED
    assert result.quarantine_path is not None
    (stored_baseline,) = baselines.by_id.values()
    assert stored_baseline.is_active is False
    (action,) = actions.by_id.values()
    assert action.action_type == RemediationActionType.QUARANTINE
    assert action.outcome == RemediationOutcome.SUCCEEDED


async def test_quarantine_use_case_rejects_deleted_change_type() -> None:
    account = _account()
    finding = _finding(account.id, change_type=ChangeType.DELETED)
    accounts = FakeCpanelAccountRepository([account])
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding

    use_case = QuarantineFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=FakeRemediationActionRepository(),
        remediator=FakeFileRemediator(),
    )

    with pytest.raises(InvariantViolationError):
        await use_case.execute(finding.id)


async def test_quarantine_use_case_raises_not_found_for_missing_finding() -> None:
    use_case = QuarantineFindingUseCase(
        finding_repository=FakeIntegrityFindingRepository(),
        account_repository=FakeCpanelAccountRepository([]),
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=FakeRemediationActionRepository(),
        remediator=FakeFileRemediator(),
    )

    with pytest.raises(EntityNotFoundError):
        await use_case.execute(uuid4())


async def test_quarantine_use_case_raises_not_found_for_missing_account() -> None:
    """A finding can outlive its account (e.g. deprovisioned between scan
    and remediation) — the use case must surface that as a 404, not a
    raw ``KeyError``/``AttributeError`` from dereferencing ``None``."""
    finding = _finding(uuid4())
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding

    use_case = QuarantineFindingUseCase(
        finding_repository=findings,
        account_repository=FakeCpanelAccountRepository([]),
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=FakeRemediationActionRepository(),
        remediator=FakeFileRemediator(),
    )

    with pytest.raises(EntityNotFoundError):
        await use_case.execute(finding.id)


async def test_quarantine_use_case_records_failed_action_on_remediation_error() -> None:
    account = _account()
    finding = _finding(account.id)
    accounts = FakeCpanelAccountRepository([account])
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    actions = FakeRemediationActionRepository()

    use_case = QuarantineFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=actions,
        remediator=FakeFileRemediator(fail=True),
    )

    with pytest.raises(FileRemediationError):
        await use_case.execute(finding.id)

    assert finding.remediation_state == RemediationState.NONE
    (action,) = actions.by_id.values()
    assert action.outcome == RemediationOutcome.FAILED


async def test_restore_use_case_records_failed_action_on_remediation_error() -> None:
    account = _account()
    finding = _finding(account.id)
    finding.quarantine(
        quarantine_path="/quarantine/x",
        mode="644",
        size_bytes=100,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )
    accounts = FakeCpanelAccountRepository([account])
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    actions = FakeRemediationActionRepository()

    use_case = RestoreFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=actions,
        remediator=FakeFileRemediator(fail=True),
    )

    with pytest.raises(FileRemediationError):
        await use_case.execute(finding.id)

    assert finding.remediation_state == RemediationState.QUARANTINED
    (action,) = actions.by_id.values()
    assert action.action_type == RemediationActionType.RESTORE
    assert action.outcome == RemediationOutcome.FAILED


async def test_restore_use_case_reactivates_baseline_and_clears_quarantine() -> None:
    account = _account()
    finding = _finding(account.id)
    finding.quarantine(
        quarantine_path="/quarantine/x",
        mode="644",
        size_bytes=100,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )
    baseline = FileBaseline(
        account_id=account.id,
        relative_path=finding.relative_path,
        sha256=Sha256Hash(value=_HASH_B),
        size_bytes=100,
        mode="644",
        last_verified_at=utcnow(),
        is_active=False,
    )
    accounts = FakeCpanelAccountRepository([account])
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    baselines = FakeFileBaselineRepository([baseline])
    actions = FakeRemediationActionRepository()

    use_case = RestoreFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=baselines,
        action_repository=actions,
        remediator=FakeFileRemediator(),
    )

    result = await use_case.execute(finding.id)

    assert result.remediation_state == RemediationState.RESTORED
    assert result.quarantine_path is None
    (stored_baseline,) = baselines.by_id.values()
    assert stored_baseline.is_active is True
    (action,) = actions.by_id.values()
    assert action.action_type == RemediationActionType.RESTORE
    assert action.outcome == RemediationOutcome.SUCCEEDED


async def test_restore_use_case_requires_quarantined_state() -> None:
    account = _account()
    finding = _finding(account.id)
    accounts = FakeCpanelAccountRepository([account])
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding

    use_case = RestoreFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=FakeRemediationActionRepository(),
        remediator=FakeFileRemediator(),
    )

    with pytest.raises(InvariantViolationError):
        await use_case.execute(finding.id)


async def test_delete_use_case_records_failed_action_on_remediation_error() -> None:
    account = _account()
    finding = _finding(account.id)
    finding.quarantine(
        quarantine_path="/quarantine/x",
        mode="644",
        size_bytes=100,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    actions = FakeRemediationActionRepository()

    use_case = DeleteFindingUseCase(
        finding_repository=findings,
        action_repository=actions,
        remediator=FakeFileRemediator(fail=True),
    )

    with pytest.raises(FileRemediationError):
        await use_case.execute(finding.id)

    assert finding.remediation_state == RemediationState.QUARANTINED
    (action,) = actions.by_id.values()
    assert action.action_type == RemediationActionType.DELETE
    assert action.outcome == RemediationOutcome.FAILED


async def test_delete_use_case_purges_quarantined_file() -> None:
    account = _account()
    finding = _finding(account.id)
    finding.quarantine(
        quarantine_path="/quarantine/x",
        mode="644",
        size_bytes=100,
        owner_uid=1000,
        owner_gid=1000,
        at=utcnow(),
    )
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    actions = FakeRemediationActionRepository()
    remediator = FakeFileRemediator()

    use_case = DeleteFindingUseCase(
        finding_repository=findings,
        action_repository=actions,
        remediator=remediator,
    )

    result = await use_case.execute(finding.id)

    assert result.remediation_state == RemediationState.DELETED
    assert remediator.purge_calls == ["/quarantine/x"]
    (action,) = actions.by_id.values()
    assert action.action_type == RemediationActionType.DELETE
    assert action.outcome == RemediationOutcome.SUCCEEDED


async def test_delete_use_case_requires_quarantined_state() -> None:
    account = _account()
    finding = _finding(account.id)
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding

    use_case = DeleteFindingUseCase(
        finding_repository=findings,
        action_repository=FakeRemediationActionRepository(),
        remediator=FakeFileRemediator(),
    )

    with pytest.raises(InvariantViolationError):
        await use_case.execute(finding.id)


def _quarantine_use_case(
    *,
    findings: FakeIntegrityFindingRepository,
    accounts: FakeCpanelAccountRepository,
    actions: FakeRemediationActionRepository,
    remediator: FakeFileRemediator | None = None,
) -> QuarantineFindingUseCase:
    return QuarantineFindingUseCase(
        finding_repository=findings,
        account_repository=accounts,
        baseline_repository=FakeFileBaselineRepository(),
        action_repository=actions,
        remediator=remediator or FakeFileRemediator(),
    )


async def test_auto_quarantine_skipped_when_mode_not_active() -> None:
    account = _account()
    finding = _finding(account.id, severity=Severity.CRITICAL)
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    accounts = FakeCpanelAccountRepository([account])
    actions = FakeRemediationActionRepository()
    events = FakeSecurityEventRepository()

    use_case = AutoQuarantineCriticalFindingsUseCase(
        finding_repository=findings,
        event_repository=events,
        quarantine_use_case=_quarantine_use_case(
            findings=findings, accounts=accounts, actions=actions
        ),
        mode="manual",
        max_per_account_per_run=5,
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_quarantined == 0
    assert result.accounts_examined == 0
    assert finding.remediation_state == RemediationState.NONE
    assert events.by_id == {}


async def test_auto_quarantine_quarantines_critical_findings_in_active_mode() -> None:
    account = _account()
    finding_a = _finding(account.id, severity=Severity.CRITICAL, relative_path="public_html/a.php")
    finding_b = _finding(account.id, severity=Severity.CRITICAL, relative_path="public_html/b.php")
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding_a.id] = finding_a
    findings.by_id[finding_b.id] = finding_b
    accounts = FakeCpanelAccountRepository([account])
    actions = FakeRemediationActionRepository()
    events = FakeSecurityEventRepository()

    use_case = AutoQuarantineCriticalFindingsUseCase(
        finding_repository=findings,
        event_repository=events,
        quarantine_use_case=_quarantine_use_case(
            findings=findings, accounts=accounts, actions=actions
        ),
        mode="active",
        max_per_account_per_run=5,
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_quarantined == 2
    assert result.accounts_examined == 1
    assert result.circuit_breaker_trips == 0
    assert finding_a.remediation_state == RemediationState.QUARANTINED
    assert finding_b.remediation_state == RemediationState.QUARANTINED
    assert all(
        action.detail is not None and action.detail.startswith("auto:")
        for action in actions.by_id.values()
    )
    assert events.by_id == {}


async def test_auto_quarantine_ignores_non_critical_findings() -> None:
    account = _account()
    finding = _finding(account.id, severity=Severity.HIGH)
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    accounts = FakeCpanelAccountRepository([account])
    actions = FakeRemediationActionRepository()

    use_case = AutoQuarantineCriticalFindingsUseCase(
        finding_repository=findings,
        event_repository=FakeSecurityEventRepository(),
        quarantine_use_case=_quarantine_use_case(
            findings=findings, accounts=accounts, actions=actions
        ),
        mode="active",
        max_per_account_per_run=5,
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_quarantined == 0
    assert finding.remediation_state == RemediationState.NONE


async def test_auto_quarantine_circuit_breaker_caps_per_account_and_raises_event() -> None:
    account = _account()
    now = utcnow()
    critical_findings = [
        _finding(
            account.id,
            severity=Severity.CRITICAL,
            relative_path=f"public_html/shell{i}.php",
            detected_at=now - timedelta(minutes=10 - i),
        )
        for i in range(3)
    ]
    findings = FakeIntegrityFindingRepository()
    for finding in critical_findings:
        findings.by_id[finding.id] = finding
    accounts = FakeCpanelAccountRepository([account])
    actions = FakeRemediationActionRepository()
    events = FakeSecurityEventRepository()

    use_case = AutoQuarantineCriticalFindingsUseCase(
        finding_repository=findings,
        event_repository=events,
        quarantine_use_case=_quarantine_use_case(
            findings=findings, accounts=accounts, actions=actions
        ),
        mode="active",
        max_per_account_per_run=2,
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_quarantined == 2
    assert result.circuit_breaker_trips == 1
    quarantined = [
        f for f in critical_findings if f.remediation_state == RemediationState.QUARANTINED
    ]
    untouched = [f for f in critical_findings if f.remediation_state == RemediationState.NONE]
    assert len(quarantined) == 2
    assert len(untouched) == 1
    # Oldest-first: the two oldest (i=0, i=1) get quarantined, the newest is left.
    assert untouched[0].relative_path == critical_findings[2].relative_path

    (event,) = events.by_id.values()
    assert event.event_type == "auto_quarantine_circuit_breaker_tripped"
    assert event.severity == Severity.CRITICAL
    assert event.account_id == account.id
    assert event.payload["quarantined_this_run"] == 2
    assert event.payload["remaining_unremediated"] == 1
    assert event.payload["max_per_account_per_run"] == 2


async def test_auto_quarantine_processes_multiple_accounts_independently() -> None:
    account_a = _account()
    account_b = _account()
    finding_a = _finding(
        account_a.id, severity=Severity.CRITICAL, relative_path="public_html/a.php"
    )
    finding_b = _finding(
        account_b.id, severity=Severity.CRITICAL, relative_path="public_html/b.php"
    )
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding_a.id] = finding_a
    findings.by_id[finding_b.id] = finding_b
    accounts = FakeCpanelAccountRepository([account_a, account_b])
    actions = FakeRemediationActionRepository()

    use_case = AutoQuarantineCriticalFindingsUseCase(
        finding_repository=findings,
        event_repository=FakeSecurityEventRepository(),
        quarantine_use_case=_quarantine_use_case(
            findings=findings, accounts=accounts, actions=actions
        ),
        mode="active",
        max_per_account_per_run=5,
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.accounts_examined == 2
    assert result.findings_quarantined == 2
    assert finding_a.remediation_state == RemediationState.QUARANTINED
    assert finding_b.remediation_state == RemediationState.QUARANTINED


async def test_auto_quarantine_tolerates_individual_quarantine_failure() -> None:
    account = _account()
    finding = _finding(account.id, severity=Severity.CRITICAL)
    findings = FakeIntegrityFindingRepository()
    findings.by_id[finding.id] = finding
    accounts = FakeCpanelAccountRepository([account])
    actions = FakeRemediationActionRepository()

    use_case = AutoQuarantineCriticalFindingsUseCase(
        finding_repository=findings,
        event_repository=FakeSecurityEventRepository(),
        quarantine_use_case=_quarantine_use_case(
            findings=findings,
            accounts=accounts,
            actions=actions,
            remediator=FakeFileRemediator(fail=True),
        ),
        mode="active",
        max_per_account_per_run=5,
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_quarantined == 0
    assert finding.remediation_state == RemediationState.NONE
    (action,) = actions.by_id.values()
    assert action.outcome == RemediationOutcome.FAILED
