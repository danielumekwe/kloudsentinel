from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.forensics.ports import TempFileObservationRepository
from sentinel.domain.forensics.value_objects import TempFileVerdict
from sentinel.domain.integrity.ports import IntegrityFindingRepository
from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.observability.ports import JobHeartbeatRepository


@dataclass(frozen=True)
class SystemStatus:
    heartbeats: list[JobHeartbeat]
    events_total: int
    events_unprocessed: int
    integrity_findings_total: int
    temp_files_malicious: int
    temp_files_suspicious: int


class GetSystemStatusQuery:
    """Aggregates the counters `sentinel health`/`sentinel status` report.

    Reads only — this exists because the CLI is a third process with no
    other way to observe what the worker's scheduler and scanners have been
    doing, short of reading the same rows they wrote.
    """

    def __init__(
        self,
        *,
        heartbeat_repository: JobHeartbeatRepository,
        event_repository: SecurityEventRepository,
        finding_repository: IntegrityFindingRepository,
        observation_repository: TempFileObservationRepository,
    ) -> None:
        self._heartbeats = heartbeat_repository
        self._events = event_repository
        self._findings = finding_repository
        self._observations = observation_repository

    async def execute(self) -> SystemStatus:
        return SystemStatus(
            heartbeats=await self._heartbeats.list(limit=100),
            events_total=await self._events.count_total(),
            events_unprocessed=await self._events.count_unprocessed(),
            integrity_findings_total=await self._findings.count_total(),
            temp_files_malicious=await self._observations.count_by_verdict(
                TempFileVerdict.MALICIOUS
            ),
            temp_files_suspicious=await self._observations.count_by_verdict(
                TempFileVerdict.SUSPICIOUS
            ),
        )
