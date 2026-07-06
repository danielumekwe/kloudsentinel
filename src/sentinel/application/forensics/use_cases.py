from __future__ import annotations

from dataclasses import dataclass

import structlog

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.forensics.ports import TempFileObservationRepository, TempFileScanner
from sentinel.domain.forensics.value_objects import TempFileVerdict
from sentinel.domain.shared.value_objects import Severity

logger = structlog.get_logger()

_SEVERITY_BY_VERDICT: dict[TempFileVerdict, Severity] = {
    TempFileVerdict.MALICIOUS: Severity.CRITICAL,
    TempFileVerdict.SUSPICIOUS: Severity.MEDIUM,
}


@dataclass(frozen=True)
class TempFileScanResult:
    files_observed: int
    events_raised: int


class ScanTempDirectoriesUseCase:
    """Watches configured temp directories for new script-like files and
    raises a ``SecurityEvent`` for anything above ``LEGITIMATE`` — the raw
    detection feed ``application.intelligence.RunCorrelationUseCase`` reads
    and groups into incidents.

    A file is only ever processed once: its ``absolute_path`` is checked
    against already-persisted observations first, so a slow/looping scan
    interval never raises duplicate events for the same file.
    """

    def __init__(
        self,
        *,
        observation_repository: TempFileObservationRepository,
        event_repository: SecurityEventRepository,
        scanner: TempFileScanner,
    ) -> None:
        self._observations = observation_repository
        self._events = event_repository
        self._scanner = scanner

    async def execute(self) -> TempFileScanResult:
        observations = await self._scanner.scan()
        files_observed = 0
        events_raised = 0

        for observation in observations:
            existing = await self._observations.get_by_path(str(observation.absolute_path))
            if existing is not None:
                continue

            await self._observations.add(observation)
            files_observed += 1

            severity = _SEVERITY_BY_VERDICT.get(observation.verdict)
            if severity is not None:
                await self._events.add(
                    SecurityEvent(
                        event_type=f"temp_file_{observation.verdict.value.lower()}",
                        source_context="forensics",
                        account_id=observation.account_id,
                        severity=severity,
                        payload={
                            "absolute_path": str(observation.absolute_path),
                            "sha256": str(observation.sha256) if observation.sha256 else None,
                            "matched_rule_ids": list(observation.matched_rule_ids),
                            "owner": observation.owner,
                            "verdict_reason": observation.verdict_reason,
                        },
                        occurred_at=observation.detected_at,
                    )
                )
                events_raised += 1

        logger.info(
            "temp_file_scan_completed", files_observed=files_observed, events_raised=events_raised
        )
        return TempFileScanResult(files_observed=files_observed, events_raised=events_raised)
