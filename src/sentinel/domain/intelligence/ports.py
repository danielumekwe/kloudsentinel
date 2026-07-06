from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from sentinel.domain.intelligence.entities import (
    Incident,
    IncidentAccountLink,
    ThreatTimelineEntry,
)
from sentinel.domain.shared.ports import Repository


class IncidentRepository(Repository[Incident], Protocol):
    async def find_open_matching(self, signature: str, *, since: datetime) -> Incident | None: ...

    async def list_open(self) -> list[Incident]: ...


class IncidentAccountLinkRepository(Repository[IncidentAccountLink], Protocol):
    async def get_by_incident_and_account(
        self, incident_id: UUID, account_id: UUID
    ) -> IncidentAccountLink | None: ...

    async def list_by_incident(self, incident_id: UUID) -> list[IncidentAccountLink]: ...


class ThreatTimelineEntryRepository(Repository[ThreatTimelineEntry], Protocol):
    async def list_by_incident(self, incident_id: UUID) -> list[ThreatTimelineEntry]: ...
