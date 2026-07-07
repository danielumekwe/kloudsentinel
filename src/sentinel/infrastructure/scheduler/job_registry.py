from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import uuid4

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.application.discovery.use_cases import RunDiscoveryUseCase
from sentinel.application.forensics.use_cases import ScanTempDirectoriesUseCase
from sentinel.application.integrity.use_cases import (
    AutoQuarantineCriticalFindingsUseCase,
    QuarantineFindingUseCase,
    RunIntegrityScanUseCase,
)
from sentinel.application.intelligence.use_cases import (
    AnalyzeRootCauseUseCase,
    RunCorrelationUseCase,
)
from sentinel.application.inventory.use_cases import RunInventoryScanUseCase
from sentinel.application.monitoring.use_cases import RunConfigurationScanUseCase
from sentinel.application.wordpress.forensic.use_cases import RunWordPressForensicScanUseCase
from sentinel.application.wordpress.integrity.use_cases import AnalyzeWordPressIntegrityUseCase
from sentinel.application.wordpress.inventory.use_cases import RunWordPressInventoryUseCase
from sentinel.config import Settings
from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.observability.value_objects import JobHeartbeatStatus
from sentinel.domain.shared.entity import utcnow
from sentinel.infrastructure.cpanel.trueuserdomains_reader import TrueUserDomainsReader
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator
from sentinel.infrastructure.filesystem.file_scanner import FilesystemFileScanner
from sentinel.infrastructure.forensics.temp_file_scanner import FilesystemTempFileScanner
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner
from sentinel.infrastructure.host_info_provider import SystemHostInfoProvider
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
    SqlAlchemyServerRepository,
    SqlAlchemyWordPressInstallationRepository,
)
from sentinel.infrastructure.persistence.repositories.events import SqlAlchemyEventRepository
from sentinel.infrastructure.persistence.repositories.forensics import (
    SqlAlchemyTempFileObservationRepository,
)
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
    SqlAlchemyRemediationActionRepository,
)
from sentinel.infrastructure.persistence.repositories.intelligence import (
    SqlAlchemyIncidentAccountLinkRepository,
    SqlAlchemyIncidentRepository,
    SqlAlchemyThreatTimelineEntryRepository,
)
from sentinel.infrastructure.persistence.repositories.inventory import (
    SqlAlchemyInstalledPluginRepository,
    SqlAlchemyInstalledThemeRepository,
)
from sentinel.infrastructure.persistence.repositories.monitoring import (
    SqlAlchemyConfigurationItemRepository,
)
from sentinel.infrastructure.persistence.repositories.observability import (
    SqlAlchemyJobHeartbeatRepository,
)
from sentinel.infrastructure.persistence.repositories.wordpress_inventory import (
    SqlAlchemyWordPressCronJobRepository,
)
from sentinel.infrastructure.scheduler.apscheduler_adapter import SchedulerAdapter
from sentinel.infrastructure.wordpress.configuration_scanner import (
    FilesystemWordPressConfigurationScanner,
)
from sentinel.infrastructure.wordpress.cron_scanner import SystemCrontabScanner
from sentinel.infrastructure.wordpress.extension_scanner import FilesystemWordPressExtensionScanner
from sentinel.infrastructure.wordpress.forensic_scanner import WordPressForensicScanner
from sentinel.infrastructure.wordpress.installation_detector import FilesystemWordPressDetector

logger = structlog.get_logger()


async def _record_heartbeat(
    database: Database,
    job_id: str,
    *,
    status: JobHeartbeatStatus,
    duration_ms: float,
    error: str | None,
) -> None:
    """Recorded via its own short-lived session, independent of the job's
    own transaction — a job rolling back on failure must never also discard
    the heartbeat reporting that failure."""
    async with database.session() as session:
        repository = SqlAlchemyJobHeartbeatRepository(session)
        now = utcnow()
        existing = await repository.find_by_job_id(job_id)
        if existing is None:
            await repository.add(
                JobHeartbeat(
                    job_id=job_id,
                    status=status,
                    last_run_at=now,
                    last_duration_ms=duration_ms,
                    last_error=error,
                )
            )
        else:
            existing.record(status=status, at=now, duration_ms=duration_ms, error=error)
            await repository.save(existing)
        await session.commit()


async def _run_tracked(
    job_id: str, database: Database, body: Callable[[AsyncSession], Awaitable[None]]
) -> None:
    """Runs one job body against a fresh session, binding a per-run
    correlation id into every log line the body (or anything it calls)
    emits, and always records the outcome as a ``JobHeartbeat`` — the only
    way `sentinel health`/`status`, running in a third separate process,
    can observe what the worker's scheduler has actually been doing.
    """
    run_id = str(uuid4())
    start = time.perf_counter()
    status = JobHeartbeatStatus.SUCCESS
    error: str | None = None
    with structlog.contextvars.bound_contextvars(job_id=job_id, run_id=run_id):
        logger.info("job_started")
        try:
            async with database.session() as session:
                await body(session)
                await session.commit()
        except Exception as exc:
            status = JobHeartbeatStatus.FAILURE
            error = str(exc)
            logger.exception(f"{job_id}_job_failed")
        duration_ms = (time.perf_counter() - start) * 1000
        logger.info("job_completed", status=status.value, duration_ms=round(duration_ms, 2))

    await _record_heartbeat(database, job_id, status=status, duration_ms=duration_ms, error=error)


def register_jobs(scheduler: SchedulerAdapter, *, database: Database, settings: Settings) -> None:
    """Registers every recurring monitoring job against the scheduler.

    Jobs are added one bounded context at a time as their use cases are
    implemented (discovery in Phase 1, integrity in Phase 2, ...), so this
    function's diff in each phase is a direct, reviewable record of which
    monitoring capability went live.
    """

    async def run_discovery() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = RunDiscoveryUseCase(
                server_repository=SqlAlchemyServerRepository(session),
                account_repository=SqlAlchemyCpanelAccountRepository(session),
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                account_reader=TrueUserDomainsReader(
                    etc_directory=Path(settings.cpanel_etc_directory),
                    home_base_directory=Path(settings.cpanel_home_base_directory),
                    suspended_directory=Path(settings.cpanel_suspended_directory),
                ),
                wp_detector=FilesystemWordPressDetector(
                    max_depth=settings.wordpress_detection_max_depth,
                    excluded_directory_markers=tuple(
                        settings.wordpress_discovery_excluded_directory_markers
                    ),
                ),
                host_info=SystemHostInfoProvider(),
            )
            await use_case.execute()

        await _run_tracked("discovery", database, _body)

    scheduler.add_interval_job(
        run_discovery, minutes=settings.discovery_scan_interval_minutes, job_id="discovery"
    )

    async def run_integrity_scan() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = RunIntegrityScanUseCase(
                account_repository=SqlAlchemyCpanelAccountRepository(session),
                baseline_repository=SqlAlchemyFileBaselineRepository(session),
                finding_repository=SqlAlchemyIntegrityFindingRepository(session),
                event_repository=SqlAlchemyEventRepository(session),
                scanner=FilesystemFileScanner(
                    excluded_relative_paths=settings.integrity_excluded_relative_paths,
                    max_file_size_bytes=settings.integrity_max_file_size_bytes,
                ),
            )
            await use_case.execute()

        await _run_tracked("integrity", database, _body)

    scheduler.add_interval_job(
        run_integrity_scan, minutes=settings.integrity_scan_interval_minutes, job_id="integrity"
    )

    async def run_inventory_scan() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = RunInventoryScanUseCase(
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                plugin_repository=SqlAlchemyInstalledPluginRepository(session),
                theme_repository=SqlAlchemyInstalledThemeRepository(session),
                extension_scanner=FilesystemWordPressExtensionScanner(),
            )
            await use_case.execute()

        await _run_tracked("inventory", database, _body)

    scheduler.add_interval_job(
        run_inventory_scan,
        minutes=settings.inventory_scan_interval_minutes,
        job_id="inventory",
    )

    async def run_configuration_scan() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = RunConfigurationScanUseCase(
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                item_repository=SqlAlchemyConfigurationItemRepository(session),
                config_scanner=FilesystemWordPressConfigurationScanner(),
            )
            await use_case.execute()

        await _run_tracked("configuration", database, _body)

    scheduler.add_interval_job(
        run_configuration_scan,
        minutes=settings.monitoring_scan_interval_minutes,
        job_id="configuration",
    )

    async def run_temp_file_scan() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = ScanTempDirectoriesUseCase(
                observation_repository=SqlAlchemyTempFileObservationRepository(session),
                event_repository=SqlAlchemyEventRepository(session),
                scanner=FilesystemTempFileScanner(
                    directories=settings.forensics_temp_directories,
                    watched_extensions=settings.forensics_watched_extensions,
                    php_malware_scanner=PhpMalwareScanner(),
                    account_repository=SqlAlchemyCpanelAccountRepository(session),
                ),
            )
            await use_case.execute()

        await _run_tracked("temp_file_scan", database, _body)

    scheduler.add_interval_job(
        run_temp_file_scan,
        minutes=settings.forensics_scan_interval_minutes,
        job_id="temp_file_scan",
    )

    async def run_correlation() -> None:
        async def _body(session: AsyncSession) -> None:
            correlation_use_case = RunCorrelationUseCase(
                event_repository=SqlAlchemyEventRepository(session),
                incident_repository=SqlAlchemyIncidentRepository(session),
                link_repository=SqlAlchemyIncidentAccountLinkRepository(session),
                timeline_repository=SqlAlchemyThreatTimelineEntryRepository(session),
                time_window_minutes=settings.correlation_time_window_minutes,
            )
            root_cause_use_case = AnalyzeRootCauseUseCase(
                incident_repository=SqlAlchemyIncidentRepository(session),
                link_repository=SqlAlchemyIncidentAccountLinkRepository(session),
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                plugin_repository=SqlAlchemyInstalledPluginRepository(session),
            )
            await correlation_use_case.execute()
            await root_cause_use_case.execute()

        await _run_tracked("correlation", database, _body)

    scheduler.add_interval_job(
        run_correlation,
        minutes=settings.correlation_interval_minutes,
        job_id="correlation",
    )

    async def run_wordpress_inventory() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = RunWordPressInventoryUseCase(
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                account_repository=SqlAlchemyCpanelAccountRepository(session),
                plugin_repository=SqlAlchemyInstalledPluginRepository(session),
                theme_repository=SqlAlchemyInstalledThemeRepository(session),
                cron_job_repository=SqlAlchemyWordPressCronJobRepository(session),
                event_repository=SqlAlchemyEventRepository(session),
                cron_scanner=SystemCrontabScanner(
                    crontab_directory=settings.wordpress_crontab_directory
                ),
                suspicious_cron_markers=settings.wordpress_suspicious_cron_markers,
            )
            await use_case.execute()

        await _run_tracked("wordpress_inventory", database, _body)

    scheduler.add_interval_job(
        run_wordpress_inventory,
        minutes=settings.wordpress_inventory_scan_interval_minutes,
        job_id="wordpress_inventory",
    )

    async def run_wordpress_integrity_audit() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = AnalyzeWordPressIntegrityUseCase(
                finding_repository=SqlAlchemyIntegrityFindingRepository(session),
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                event_repository=SqlAlchemyEventRepository(session),
                critical_relative_paths=settings.wordpress_critical_relative_paths,
                lookback_minutes=settings.wordpress_integrity_audit_interval_minutes,
            )
            await use_case.execute()

        await _run_tracked("wordpress_integrity_audit", database, _body)

    scheduler.add_interval_job(
        run_wordpress_integrity_audit,
        minutes=settings.wordpress_integrity_audit_interval_minutes,
        job_id="wordpress_integrity_audit",
    )

    async def run_wordpress_forensic_scan() -> None:
        async def _body(session: AsyncSession) -> None:
            use_case = RunWordPressForensicScanUseCase(
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                account_repository=SqlAlchemyCpanelAccountRepository(session),
                cron_job_repository=SqlAlchemyWordPressCronJobRepository(session),
                event_repository=SqlAlchemyEventRepository(session),
                finding_repository=SqlAlchemyIntegrityFindingRepository(session),
                scanner=WordPressForensicScanner(
                    php_malware_scanner=PhpMalwareScanner(),
                    dropin_relative_paths=settings.wordpress_dropin_relative_paths,
                ),
            )
            await use_case.execute()

        await _run_tracked("wordpress_forensic_scan", database, _body)

    scheduler.add_interval_job(
        run_wordpress_forensic_scan,
        minutes=settings.wordpress_forensic_scan_interval_minutes,
        job_id="wordpress_forensic_scan",
    )

    async def run_auto_quarantine() -> None:
        async def _body(session: AsyncSession) -> None:
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
                lookback_minutes=settings.auto_quarantine_interval_minutes,
            )
            await use_case.execute()

        await _run_tracked("auto_quarantine", database, _body)

    scheduler.add_interval_job(
        run_auto_quarantine,
        minutes=settings.auto_quarantine_interval_minutes,
        job_id="auto_quarantine",
    )
