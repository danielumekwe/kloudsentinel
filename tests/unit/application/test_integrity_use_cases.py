from __future__ import annotations

from uuid import UUID, uuid4

from sentinel.application.integrity.use_cases import RunIntegrityScanUseCase
from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding
from sentinel.domain.integrity.value_objects import ChangeType, ScannedFile
from sentinel.domain.shared.entity import utcnow
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


class FakeFileScanner:
    def __init__(self, by_account_id: dict[UUID, list[ScannedFile]]) -> None:
        self._by_account_id = by_account_id

    async def scan(self, account: CpanelAccount) -> list[ScannedFile]:
        return self._by_account_id.get(account.id, [])


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


async def test_first_scan_establishes_baselines_without_findings() -> None:
    account = _account()
    accounts = FakeCpanelAccountRepository([account])
    baselines = FakeFileBaselineRepository()
    findings = FakeIntegrityFindingRepository()
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_A)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
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
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_A)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
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
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_B)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
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
    scanner = FakeFileScanner({account.id: []})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
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
    scanner = FakeFileScanner(
        {account.id: [_scanned_file("public_html/wp-config.php", _HASH_A, mode="666")]}
    )

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
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
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_A)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
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
    scanner = FakeFileScanner({account.id: [_scanned_file("public_html/index.php", _HASH_B)]})

    use_case = RunIntegrityScanUseCase(
        account_repository=accounts,
        baseline_repository=baselines,
        finding_repository=findings,
        scanner=scanner,
    )

    await use_case.execute()

    assert len(baselines.by_id) == 1
    (baseline,) = baselines.by_id.values()
    assert baseline.is_active is True
    assert str(baseline.sha256) == _HASH_B
    (finding,) = findings.by_id.values()
    assert finding.change_type == ChangeType.ADDED
