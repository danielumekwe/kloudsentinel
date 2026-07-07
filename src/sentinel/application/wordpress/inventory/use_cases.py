from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import CpanelAccount
from sentinel.domain.discovery.ports import CpanelAccountRepository, WordPressInstallationRepository
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.inventory.ports import InstalledPluginRepository, InstalledThemeRepository
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import Severity
from sentinel.domain.wordpress.inventory.entities import WordPressCronJob
from sentinel.domain.wordpress.inventory.ports import WordPressCronJobRepository
from sentinel.infrastructure.wordpress.cron_scanner import SystemCrontabScanner

logger = structlog.get_logger()


@dataclass(frozen=True)
class WordPressInventoryResult:
    installations_scanned: int
    cron_jobs_found: int
    suspicious_cron_jobs: int


class RunWordPressInventoryUseCase:
    """Extends the existing plugin/theme inventory (already handled by
    ``RunInventoryScanUseCase``, reused unchanged and run separately) with
    WordPress-specific facts a filesystem-only agent can actually observe:
    system-crontab entries per account, plus a point-in-time snapshot event
    for history — reusing the event log rather than a new snapshot table,
    since current-state inventory tables everywhere else in this codebase
    are upsert-only.
    """

    def __init__(
        self,
        *,
        installation_repository: WordPressInstallationRepository,
        account_repository: CpanelAccountRepository,
        plugin_repository: InstalledPluginRepository,
        theme_repository: InstalledThemeRepository,
        cron_job_repository: WordPressCronJobRepository,
        event_repository: SecurityEventRepository,
        cron_scanner: SystemCrontabScanner,
        suspicious_cron_markers: list[str],
    ) -> None:
        self._installations = installation_repository
        self._accounts = account_repository
        self._plugins = plugin_repository
        self._themes = theme_repository
        self._cron_jobs = cron_job_repository
        self._events = event_repository
        self._cron_scanner = cron_scanner
        self._suspicious_markers = [marker.lower() for marker in suspicious_cron_markers]

    async def execute(self) -> WordPressInventoryResult:
        installations_scanned = 0
        cron_jobs_found = 0
        suspicious_cron_jobs = 0
        now = utcnow()

        for installation in await self._installations.list(limit=10_000):
            if not installation.is_active:
                continue
            account = await self._accounts.get(installation.cpanel_account_id)
            if account is None:
                continue

            installations_scanned += 1
            found, suspicious = await self._reconcile_cron_jobs(installation.id, account, at=now)
            cron_jobs_found += found
            suspicious_cron_jobs += suspicious

            await self._emit_snapshot(installation.id, account_id=account.id, at=now)

        logger.info(
            "wordpress_inventory_completed",
            installations_scanned=installations_scanned,
            cron_jobs_found=cron_jobs_found,
            suspicious_cron_jobs=suspicious_cron_jobs,
        )
        return WordPressInventoryResult(
            installations_scanned=installations_scanned,
            cron_jobs_found=cron_jobs_found,
            suspicious_cron_jobs=suspicious_cron_jobs,
        )

    async def _reconcile_cron_jobs(
        self, installation_id: UUID, account: CpanelAccount, *, at: datetime
    ) -> tuple[int, int]:
        entries = await self._cron_scanner.scan(account)
        existing = {
            job.command: job for job in await self._cron_jobs.list_by_installation(installation_id)
        }
        seen_commands: set[str] = set()
        suspicious_count = 0

        for entry in entries:
            seen_commands.add(entry.command)
            is_suspicious, flag_reason = self._classify(entry.command)
            if is_suspicious:
                suspicious_count += 1

            job = existing.get(entry.command)
            if job is None:
                await self._cron_jobs.add(
                    WordPressCronJob(
                        installation_id=installation_id,
                        command=entry.command,
                        schedule_raw=entry.schedule_raw,
                        is_suspicious=is_suspicious,
                        flag_reason=flag_reason,
                        last_seen_at=at,
                    )
                )
            else:
                job.mark_seen(
                    schedule_raw=entry.schedule_raw,
                    is_suspicious=is_suspicious,
                    flag_reason=flag_reason,
                    at=at,
                )
                await self._cron_jobs.save(job)

        for command, job in existing.items():
            if command not in seen_commands and job.is_present:
                job.mark_absent(at=at)
                await self._cron_jobs.save(job)

        return len(entries), suspicious_count

    def _classify(self, command: str) -> tuple[bool, str | None]:
        lowered = command.lower()
        for marker in self._suspicious_markers:
            if marker in lowered:
                return True, f"command contains suspicious pattern: {marker!r}"
        return False, None

    async def _emit_snapshot(
        self, installation_id: UUID, *, account_id: UUID, at: datetime
    ) -> None:
        plugins = await self._plugins.list_by_installation(installation_id)
        themes = await self._themes.list_by_installation(installation_id)
        cron_jobs = await self._cron_jobs.list_by_installation(installation_id)

        await self._events.add(
            SecurityEvent(
                event_type="wordpress_inventory_snapshot",
                source_context="wordpress",
                account_id=account_id,
                severity=Severity.INFO,
                payload={
                    "installation_id": str(installation_id),
                    "plugin_count": sum(1 for p in plugins if p.is_present),
                    "theme_count": sum(1 for t in themes if t.is_present),
                    "cron_job_count": sum(1 for c in cron_jobs if c.is_present),
                    "plugins": [
                        {"slug": p.slug, "version": p.version} for p in plugins if p.is_present
                    ],
                    "themes": [
                        {"slug": t.slug, "version": t.version} for t in themes if t.is_present
                    ],
                },
                occurred_at=at,
            )
        )
