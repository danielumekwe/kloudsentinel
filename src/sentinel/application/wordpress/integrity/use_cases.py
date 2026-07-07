from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import structlog

from sentinel.domain.discovery.ports import WordPressInstallationRepository
from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.integrity.ports import IntegrityFindingRepository
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import Severity

logger = structlog.get_logger()


@dataclass(frozen=True)
class WordPressIntegrityAuditResult:
    findings_examined: int
    critical_findings_flagged: int


class AnalyzeWordPressIntegrityUseCase:
    """Runs after the existing ``RunIntegrityScanUseCase`` (unchanged, not
    duplicated) and re-reads recently-detected ``IntegrityFinding`` rows,
    elevating anything that touches one of the named WordPress-core
    critical paths to CRITICAL severity — both on the finding itself (via
    ``IntegrityFinding.escalate_severity``, so it becomes eligible for
    auto-quarantine and shows CRITICAL everywhere the finding is surfaced)
    and via a dedicated ``wordpress_core_file_modified`` event.

    Today's integrity severity is change-type-only (``ADDED`` -> MEDIUM,
    etc.) — appropriate for a random file under an account's home
    directory, but it under-weights e.g. a brand-new
    ``wp-content/db.php`` (an ``ADDED`` finding, MEDIUM by default) which is
    one of the most common malware-persistence drop-ins on WordPress.
    """

    def __init__(
        self,
        *,
        finding_repository: IntegrityFindingRepository,
        installation_repository: WordPressInstallationRepository,
        event_repository: SecurityEventRepository,
        critical_relative_paths: list[str],
        lookback_minutes: int,
    ) -> None:
        self._findings = finding_repository
        self._installations = installation_repository
        self._events = event_repository
        self._critical_paths = set(critical_relative_paths)
        self._lookback_minutes = lookback_minutes

    async def execute(self) -> WordPressIntegrityAuditResult:
        since = utcnow() - timedelta(minutes=self._lookback_minutes)
        findings = await self._findings.list_since(since, limit=500)

        examined = 0
        flagged = 0
        for finding in findings:
            if str(finding.relative_path) not in self._critical_paths:
                continue
            examined += 1

            installations = await self._installations.list_by_account(finding.account_id)
            if not installations:
                continue

            if finding.severity.rank < Severity.CRITICAL.rank:
                finding.escalate_severity(Severity.CRITICAL, at=finding.detected_at)
                await self._findings.save(finding)

            await self._events.add(
                SecurityEvent(
                    event_type="wordpress_core_file_modified",
                    source_context="wordpress",
                    account_id=finding.account_id,
                    severity=Severity.CRITICAL,
                    payload={
                        "finding_id": str(finding.id),
                        "relative_path": str(finding.relative_path),
                        "change_type": finding.change_type.value,
                    },
                    occurred_at=finding.detected_at,
                    file_path=str(finding.relative_path),
                    sha256=str(finding.current_sha256) if finding.current_sha256 else None,
                    detection_rule_id="wordpress-critical-file",
                    scanner_version="wordpress-integrity@1",
                )
            )
            flagged += 1

        logger.info(
            "wordpress_integrity_audit_completed",
            findings_examined=examined,
            critical_findings_flagged=flagged,
        )
        return WordPressIntegrityAuditResult(
            findings_examined=examined, critical_findings_flagged=flagged
        )
