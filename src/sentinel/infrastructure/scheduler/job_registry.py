from __future__ import annotations

from pathlib import Path

import structlog

from sentinel.application.discovery.use_cases import RunDiscoveryUseCase
from sentinel.application.integrity.use_cases import RunIntegrityScanUseCase
from sentinel.application.inventory.use_cases import RunInventoryScanUseCase
from sentinel.application.monitoring.use_cases import RunConfigurationScanUseCase
from sentinel.config import Settings
from sentinel.infrastructure.cpanel.trueuserdomains_reader import TrueUserDomainsReader
from sentinel.infrastructure.filesystem.file_scanner import FilesystemFileScanner
from sentinel.infrastructure.host_info_provider import SystemHostInfoProvider
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
    SqlAlchemyServerRepository,
    SqlAlchemyWordPressInstallationRepository,
)
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
)
from sentinel.infrastructure.persistence.repositories.inventory import (
    SqlAlchemyInstalledPluginRepository,
    SqlAlchemyInstalledThemeRepository,
)
from sentinel.infrastructure.persistence.repositories.monitoring import (
    SqlAlchemyConfigurationItemRepository,
)
from sentinel.infrastructure.scheduler.apscheduler_adapter import SchedulerAdapter
from sentinel.infrastructure.wordpress.configuration_scanner import (
    FilesystemWordPressConfigurationScanner,
)
from sentinel.infrastructure.wordpress.extension_scanner import FilesystemWordPressExtensionScanner
from sentinel.infrastructure.wordpress.installation_detector import FilesystemWordPressDetector

logger = structlog.get_logger()


def register_jobs(scheduler: SchedulerAdapter, *, database: Database, settings: Settings) -> None:
    """Registers every recurring monitoring job against the scheduler.

    Jobs are added one bounded context at a time as their use cases are
    implemented (discovery in Phase 1, integrity in Phase 2, ...), so this
    function's diff in each phase is a direct, reviewable record of which
    monitoring capability went live.
    """

    async def run_discovery() -> None:
        async with database.session() as session:
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
                    max_depth=settings.wordpress_detection_max_depth
                ),
                host_info=SystemHostInfoProvider(),
            )
            try:
                await use_case.execute()
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception("discovery_job_failed")

    scheduler.add_interval_job(
        run_discovery, minutes=settings.discovery_scan_interval_minutes, job_id="discovery"
    )

    async def run_integrity_scan() -> None:
        async with database.session() as session:
            use_case = RunIntegrityScanUseCase(
                account_repository=SqlAlchemyCpanelAccountRepository(session),
                baseline_repository=SqlAlchemyFileBaselineRepository(session),
                finding_repository=SqlAlchemyIntegrityFindingRepository(session),
                scanner=FilesystemFileScanner(
                    excluded_relative_paths=settings.integrity_excluded_relative_paths,
                    max_file_size_bytes=settings.integrity_max_file_size_bytes,
                ),
            )
            try:
                await use_case.execute()
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception("integrity_scan_job_failed")

    scheduler.add_interval_job(
        run_integrity_scan, minutes=settings.integrity_scan_interval_minutes, job_id="integrity"
    )

    async def run_inventory_scan() -> None:
        async with database.session() as session:
            use_case = RunInventoryScanUseCase(
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                plugin_repository=SqlAlchemyInstalledPluginRepository(session),
                theme_repository=SqlAlchemyInstalledThemeRepository(session),
                extension_scanner=FilesystemWordPressExtensionScanner(),
            )
            try:
                await use_case.execute()
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception("inventory_scan_job_failed")

    scheduler.add_interval_job(
        run_inventory_scan,
        minutes=settings.inventory_scan_interval_minutes,
        job_id="inventory",
    )

    async def run_configuration_scan() -> None:
        async with database.session() as session:
            use_case = RunConfigurationScanUseCase(
                installation_repository=SqlAlchemyWordPressInstallationRepository(session),
                item_repository=SqlAlchemyConfigurationItemRepository(session),
                config_scanner=FilesystemWordPressConfigurationScanner(),
            )
            try:
                await use_case.execute()
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception("configuration_scan_job_failed")

    scheduler.add_interval_job(
        run_configuration_scan,
        minutes=settings.monitoring_scan_interval_minutes,
        job_id="configuration",
    )
