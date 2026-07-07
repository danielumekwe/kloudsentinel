from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest

from sentinel.application.wordpress.integrity.checksum_use_cases import VerifyCoreChecksumsUseCase
from sentinel.application.wordpress.integrity.use_cases import AnalyzeWordPressIntegrityUseCase
from sentinel.domain.discovery.entities import WordPressInstallation
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding
from sentinel.domain.integrity.value_objects import ChangeType
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import (
    AbsoluteFilePath,
    DomainName,
    RelativeFilePath,
    Severity,
    Sha256Hash,
)
from sentinel.domain.wordpress.integrity.entities import CoreChecksumRecord

_HASH_A = "a" * 64
_HASH_B = "b" * 64


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

    async def list_since(self, since: datetime, *, limit: int = 500) -> list[IntegrityFinding]:
        return [f for f in self.by_id.values() if f.detected_at >= since][:limit]


class FakeWordPressInstallationRepository:
    def __init__(self, installations: list[WordPressInstallation] | None = None) -> None:
        self.by_id: dict[UUID, WordPressInstallation] = {i.id: i for i in installations or []}

    async def add(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: WordPressInstallation) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> WordPressInstallation | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressInstallation]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None:
        return next((i for i in self.by_id.values() if str(i.absolute_path) == absolute_path), None)

    async def list_by_account(self, cpanel_account_id: UUID) -> list[WordPressInstallation]:
        return [i for i in self.by_id.values() if i.cpanel_account_id == cpanel_account_id]


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

    async def list_by_account(self, account_id: UUID, *, limit: int = 200) -> list[SecurityEvent]:
        return [e for e in self.by_id.values() if e.account_id == account_id][:limit]


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


class FakeCoreChecksumRepository:
    def __init__(self, records: list[CoreChecksumRecord] | None = None) -> None:
        self.by_id: dict[UUID, CoreChecksumRecord] = {r.id: r for r in records or []}

    async def add(self, entity: CoreChecksumRecord) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: CoreChecksumRecord) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> CoreChecksumRecord | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CoreChecksumRecord]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_version_and_path(
        self, wp_version: str, relative_path: str
    ) -> CoreChecksumRecord | None:
        return next(
            (
                r
                for r in self.by_id.values()
                if r.wp_version == wp_version and r.relative_path == relative_path
            ),
            None,
        )

    async def list_by_version(self, wp_version: str) -> list[CoreChecksumRecord]:
        return [r for r in self.by_id.values() if r.wp_version == wp_version]

    async def has_version(self, wp_version: str) -> bool:
        return any(r.wp_version == wp_version for r in self.by_id.values())


class FakeChecksumsClient:
    def __init__(self, checksums: dict[str, str]) -> None:
        self._checksums = checksums
        self.calls = 0

    async def fetch_checksums(self, wp_version: str) -> dict[str, str]:
        self.calls += 1
        return dict(self._checksums)


def _installation(*, account_id: UUID, wp_version: str | None = "6.5") -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=account_id,
        absolute_path=AbsoluteFilePath(value="/home/examplebob1/public_html"),
        domain=DomainName(value="example.com"),
        wp_version=wp_version,
        is_multisite=False,
        last_seen_at=utcnow(),
    )


def _finding(*, account_id: UUID, relative_path: str, detected_at: datetime) -> IntegrityFinding:
    return IntegrityFinding(
        account_id=account_id,
        relative_path=RelativeFilePath(value=relative_path),
        change_type=ChangeType.ADDED,
        severity=Severity.MEDIUM,
        previous_sha256=None,
        current_sha256=Sha256Hash(value=_HASH_B),
        detected_at=detected_at,
    )


async def test_analyze_wordpress_integrity_flags_critical_path_as_critical_event() -> None:
    account_id = uuid4()
    installation = _installation(account_id=account_id)
    now = utcnow()
    finding = _finding(account_id=account_id, relative_path="wp-content/db.php", detected_at=now)

    findings = FakeIntegrityFindingRepository([finding])
    installations = FakeWordPressInstallationRepository([installation])
    events = FakeSecurityEventRepository()

    use_case = AnalyzeWordPressIntegrityUseCase(
        finding_repository=findings,
        installation_repository=installations,
        event_repository=events,
        critical_relative_paths=["wp-content/db.php", "index.php"],
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_examined == 1
    assert result.critical_findings_flagged == 1
    (event,) = events.by_id.values()
    assert event.event_type == "wordpress_core_file_modified"
    assert event.severity == Severity.CRITICAL
    assert event.account_id == account_id
    assert event.file_path == "wp-content/db.php"
    assert event.sha256 == _HASH_B
    # The finding itself is escalated (and persisted), not just the event —
    # this is what makes it eligible for AutoQuarantineCriticalFindingsUseCase.
    assert finding.severity is Severity.CRITICAL
    assert findings.by_id[finding.id].severity is Severity.CRITICAL


async def test_analyze_wordpress_integrity_does_not_re_escalate_already_critical_finding() -> None:
    """A finding already at CRITICAL (e.g. re-examined on a later run
    within the lookback window) must not be re-escalated —
    ``IntegrityFinding.escalate_severity`` rejects a same-severity call, so
    the use case has to guard against calling it a second time."""
    account_id = uuid4()
    installation = _installation(account_id=account_id)
    now = utcnow()
    finding = _finding(account_id=account_id, relative_path="wp-content/db.php", detected_at=now)
    finding.escalate_severity(Severity.CRITICAL, at=now)

    use_case = AnalyzeWordPressIntegrityUseCase(
        finding_repository=FakeIntegrityFindingRepository([finding]),
        installation_repository=FakeWordPressInstallationRepository([installation]),
        event_repository=FakeSecurityEventRepository(),
        critical_relative_paths=["wp-content/db.php"],
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.critical_findings_flagged == 1
    assert finding.severity is Severity.CRITICAL


async def test_analyze_wordpress_integrity_ignores_non_critical_paths() -> None:
    account_id = uuid4()
    installation = _installation(account_id=account_id)
    now = utcnow()
    finding = _finding(
        account_id=account_id, relative_path="wp-content/uploads/random.jpg.php", detected_at=now
    )

    use_case = AnalyzeWordPressIntegrityUseCase(
        finding_repository=FakeIntegrityFindingRepository([finding]),
        installation_repository=FakeWordPressInstallationRepository([installation]),
        event_repository=FakeSecurityEventRepository(),
        critical_relative_paths=["wp-content/db.php", "index.php"],
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_examined == 0
    assert result.critical_findings_flagged == 0


async def test_analyze_wordpress_integrity_ignores_accounts_without_wordpress() -> None:
    account_id = uuid4()
    now = utcnow()
    finding = _finding(account_id=account_id, relative_path="index.php", detected_at=now)

    use_case = AnalyzeWordPressIntegrityUseCase(
        finding_repository=FakeIntegrityFindingRepository([finding]),
        installation_repository=FakeWordPressInstallationRepository(),
        event_repository=FakeSecurityEventRepository(),
        critical_relative_paths=["index.php"],
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.critical_findings_flagged == 0


async def test_analyze_wordpress_integrity_respects_lookback_window() -> None:
    account_id = uuid4()
    installation = _installation(account_id=account_id)
    stale_finding = _finding(
        account_id=account_id,
        relative_path="index.php",
        detected_at=utcnow() - timedelta(minutes=120),
    )

    use_case = AnalyzeWordPressIntegrityUseCase(
        finding_repository=FakeIntegrityFindingRepository([stale_finding]),
        installation_repository=FakeWordPressInstallationRepository([installation]),
        event_repository=FakeSecurityEventRepository(),
        critical_relative_paths=["index.php"],
        lookback_minutes=60,
    )

    result = await use_case.execute()

    assert result.findings_examined == 0


async def test_verify_core_checksums_reports_match_mismatch_and_not_tracked() -> None:
    account_id = uuid4()
    installation = _installation(account_id=account_id)
    baselines = FakeFileBaselineRepository(
        [
            FileBaseline(
                account_id=account_id,
                relative_path=RelativeFilePath(value="index.php"),
                sha256=Sha256Hash(value=_HASH_A),
                size_bytes=10,
                mode="644",
                last_verified_at=utcnow(),
            ),
            FileBaseline(
                account_id=account_id,
                relative_path=RelativeFilePath(value="wp-load.php"),
                sha256=Sha256Hash(value=_HASH_B),
                size_bytes=10,
                mode="644",
                last_verified_at=utcnow(),
            ),
        ]
    )
    checksums_client = FakeChecksumsClient({"index.php": _HASH_A, "wp-load.php": _HASH_A})

    use_case = VerifyCoreChecksumsUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        baseline_repository=baselines,
        checksum_repository=FakeCoreChecksumRepository(),
        checksums_client=checksums_client,
        critical_relative_paths=["index.php", "wp-load.php", "wp-content/db.php"],
    )

    results = await use_case.execute(installation.id)
    by_path = {r.relative_path: r for r in results}

    assert by_path["index.php"].status == "MATCH"
    assert by_path["wp-load.php"].status == "MISMATCH"
    assert by_path["wp-content/db.php"].status == "NOT_TRACKED"
    assert checksums_client.calls == 1


async def test_verify_core_checksums_caches_after_first_fetch() -> None:
    account_id = uuid4()
    installation = _installation(account_id=account_id)
    checksums_client = FakeChecksumsClient({"index.php": _HASH_A})
    checksum_repository = FakeCoreChecksumRepository()

    use_case = VerifyCoreChecksumsUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        baseline_repository=FakeFileBaselineRepository(),
        checksum_repository=checksum_repository,
        checksums_client=checksums_client,
        critical_relative_paths=["index.php"],
    )

    await use_case.execute(installation.id)
    await use_case.execute(installation.id)

    assert checksums_client.calls == 1


async def test_verify_core_checksums_unknown_when_wp_version_missing() -> None:
    account_id = uuid4()
    installation = _installation(account_id=account_id, wp_version=None)

    use_case = VerifyCoreChecksumsUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        baseline_repository=FakeFileBaselineRepository(),
        checksum_repository=FakeCoreChecksumRepository(),
        checksums_client=FakeChecksumsClient({}),
        critical_relative_paths=["index.php"],
    )

    results = await use_case.execute(installation.id)

    assert all(r.status == "UNKNOWN" for r in results)


async def test_verify_core_checksums_raises_for_unknown_installation() -> None:
    use_case = VerifyCoreChecksumsUseCase(
        installation_repository=FakeWordPressInstallationRepository(),
        baseline_repository=FakeFileBaselineRepository(),
        checksum_repository=FakeCoreChecksumRepository(),
        checksums_client=FakeChecksumsClient({}),
        critical_relative_paths=["index.php"],
    )

    with pytest.raises(EntityNotFoundError):
        await use_case.execute(uuid4())
