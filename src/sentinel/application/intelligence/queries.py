from __future__ import annotations

from uuid import UUID

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.events.ports import SecurityEventRepository
from sentinel.domain.intelligence.entities import Incident, ThreatTimelineEntry
from sentinel.domain.intelligence.ports import IncidentRepository, ThreatTimelineEntryRepository
from sentinel.domain.shared.exceptions import EntityNotFoundError


class ListIncidentsQuery:
    def __init__(self, incident_repository: IncidentRepository) -> None:
        self._incidents = incident_repository

    async def execute(self, *, limit: int, offset: int) -> list[Incident]:
        return await self._incidents.list(limit=limit, offset=offset)


class GetIncidentQuery:
    def __init__(self, incident_repository: IncidentRepository) -> None:
        self._incidents = incident_repository

    async def execute(self, incident_id: UUID) -> Incident:
        incident = await self._incidents.get(incident_id)
        if incident is None:
            raise EntityNotFoundError("Incident", incident_id)
        return incident


class ListIncidentTimelineQuery:
    def __init__(self, timeline_repository: ThreatTimelineEntryRepository) -> None:
        self._timeline = timeline_repository

    async def execute(self, incident_id: UUID) -> list[ThreatTimelineEntry]:
        return await self._timeline.list_by_incident(incident_id)


class ListIncidentEvidenceQuery:
    """An incident's evidence is the raw ``SecurityEvent`` rows its timeline
    entries point back to."""

    def __init__(
        self,
        timeline_repository: ThreatTimelineEntryRepository,
        event_repository: SecurityEventRepository,
    ) -> None:
        self._timeline = timeline_repository
        self._events = event_repository

    async def execute(self, incident_id: UUID) -> list[SecurityEvent]:
        entries = await self._timeline.list_by_incident(incident_id)
        events: list[SecurityEvent] = []
        for entry in entries:
            if entry.source_event_id is None:
                continue
            event = await self._events.get(entry.source_event_id)
            if event is not None:
                events.append(event)
        return events
