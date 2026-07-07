from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import UUID

import structlog

from sentinel.domain.discovery.entities import CpanelAccount, WordPressInstallation
from sentinel.domain.discovery.ports import CpanelAccountRepository, WordPressInstallationRepository
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.integrity.entities import IntegrityFinding
from sentinel.domain.integrity.ports import IntegrityFindingRepository
from sentinel.domain.integrity.value_objects import ChangeType
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash
from sentinel.domain.wordpress.forensic.value_objects import WordPressForensicFinding
from sentinel.domain.wordpress.inventory.entities import WordPressCronJob
from sentinel.domain.wordpress.inventory.ports import WordPressCronJobRepository
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner
from sentinel.infrastructure.wordpress.forensic_scanner import WordPressForensicScanner

logger = structlog.get_logger()

_SUSPICIOUS_CRON_SEVERITY = Severity.HIGH


@dataclass(frozen=True)
class WordPressForensicScanResult:
    installations_scanned: int
    findings_raised: int
    suspicious_cron_alerts: int


class RunWordPressForensicScanUseCase:
    """WordPress-specific persistence/malware detection, reusing
    ``PhpMalwareScanner`` content rules (via ``WordPressForensicScanner``)
    exactly the way the existing ``/tmp`` forensics scanner already does —
    no scanner is duplicated here, only new *structural* checks layered on
    top.

    Suspicious system-crontab entries are already recorded by
    ``RunWordPressInventoryUseCase``; this use case turns that state into an
    actual alert (an event), the same separation of concerns as
    integrity findings vs. the WordPress-critical-file severity boost. A
    still-suspicious cron entry is re-alerted on every run rather than
    deduplicated — a repeated alert for an unresolved persistence mechanism
    is preferable to a missed one.

    A CRITICAL-severity finding (a fake plugin/theme file, must-use
    plugin, hidden upload script, or drop-in that matched a malware rule)
    is also materialized as a real, quarantinable ``IntegrityFinding`` —
    the same entity ``RunIntegrityScanUseCase`` produces — so it enters
    the exact same quarantine/audit pipeline (and is eligible for
    ``AutoQuarantineCriticalFindingsUseCase``) without a second remediation
    mechanism. Anything below CRITICAL stays event-only, unchanged.
    """

    def __init__(
        self,
        *,
        installation_repository: WordPressInstallationRepository,
        account_repository: CpanelAccountRepository,
        cron_job_repository: WordPressCronJobRepository,
        event_repository: SecurityEventRepository,
        finding_repository: IntegrityFindingRepository,
        scanner: WordPressForensicScanner,
    ) -> None:
        self._installations = installation_repository
        self._accounts = account_repository
        self._cron_jobs = cron_job_repository
        self._events = event_repository
        self._findings = finding_repository
        self._scanner = scanner

    async def execute(self) -> WordPressForensicScanResult:
        installations_scanned = 0
        findings_raised = 0
        suspicious_cron_alerts = 0
        now = utcnow()

        for installation in await self._installations.list(limit=10_000):
            if not installation.is_active:
                continue
            installations_scanned += 1
            account = await self._accounts.get(installation.cpanel_account_id)

            for finding in await self._scanner.scan(installation):
                await self._raise_finding_event(installation.cpanel_account_id, finding, at=now)
                if finding.severity is Severity.CRITICAL and account is not None:
                    await self._materialize_integrity_finding(
                        account, installation, finding, at=now
                    )
                findings_raised += 1

            for cron_job in await self._cron_jobs.list_by_installation(installation.id):
                if not (cron_job.is_present and cron_job.is_suspicious):
                    continue
                await self._raise_cron_event(installation.cpanel_account_id, cron_job, at=now)
                suspicious_cron_alerts += 1

        logger.info(
            "wordpress_forensic_scan_completed",
            installations_scanned=installations_scanned,
            findings_raised=findings_raised,
            suspicious_cron_alerts=suspicious_cron_alerts,
        )
        return WordPressForensicScanResult(
            installations_scanned=installations_scanned,
            findings_raised=findings_raised,
            suspicious_cron_alerts=suspicious_cron_alerts,
        )

    async def _raise_finding_event(
        self, account_id: UUID, finding: WordPressForensicFinding, *, at: datetime
    ) -> None:
        await self._events.add(
            SecurityEvent(
                event_type=f"wordpress_{finding.finding_type}",
                source_context="wordpress",
                account_id=account_id,
                severity=finding.severity,
                payload={
                    "relative_path": finding.relative_path,
                    "description": finding.description,
                    "matched_rule_ids": list(finding.matched_rule_ids),
                },
                occurred_at=at,
                file_path=finding.relative_path,
                scanner_version=PhpMalwareScanner.VERSION,
                detection_rule_id=(
                    ",".join(finding.matched_rule_ids) if finding.matched_rule_ids else None
                ),
            )
        )

    async def _materialize_integrity_finding(
        self,
        account: CpanelAccount,
        installation: WordPressInstallation,
        finding: WordPressForensicFinding,
        *,
        at: datetime,
    ) -> None:
        """Re-anchors a CRITICAL ``WordPressForensicFinding`` (relative to
        the WP install root) onto the cPanel account's home directory and
        persists it as an ``IntegrityFinding`` — the entity every
        quarantine/restore/audit code path already understands. Silently
        skips (with a warning) the pathological case of an install
        resolved outside its own account's home directory; that's a
        discovery-layer inconsistency this use case has no business
        papering over.
        """
        absolute_path = Path(str(installation.absolute_path)) / finding.relative_path
        try:
            account_relative = absolute_path.relative_to(Path(str(account.home_directory)))
        except ValueError:
            logger.warning(
                "wordpress_forensic_finding_outside_account_home",
                installation_id=str(installation.id),
                account_id=str(account.id),
                relative_path=finding.relative_path,
            )
            return

        await self._findings.add(
            IntegrityFinding(
                account_id=account.id,
                relative_path=RelativeFilePath(value=str(account_relative)),
                change_type=ChangeType.ADDED,
                severity=Severity.CRITICAL,
                previous_sha256=None,
                current_sha256=Sha256Hash(value=finding.sha256) if finding.sha256 else None,
                detected_at=at,
            )
        )

    async def _raise_cron_event(
        self, account_id: UUID, cron_job: WordPressCronJob, *, at: datetime
    ) -> None:
        await self._events.add(
            SecurityEvent(
                event_type="wordpress_suspicious_cron",
                source_context="wordpress",
                account_id=account_id,
                severity=_SUSPICIOUS_CRON_SEVERITY,
                payload={
                    "command": cron_job.command,
                    "schedule_raw": cron_job.schedule_raw,
                    "flag_reason": cron_job.flag_reason,
                },
                occurred_at=at,
                detection_rule_id=cron_job.flag_reason,
            )
        )
