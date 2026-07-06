from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.intelligence.entities import Incident, ThreatTimelineEntry


class IncidentResponse(BaseModel):
    id: UUID
    title: str
    status: str
    severity: str
    confidence: float
    first_seen_at: datetime
    last_seen_at: datetime
    root_cause: str | None
    recommended_actions: str | None
    false_positive_probability: float | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: Incident) -> IncidentResponse:
        return cls(
            id=entity.id,
            title=entity.title,
            status=entity.status.value,
            severity=entity.severity.value,
            confidence=entity.confidence,
            first_seen_at=entity.first_seen_at,
            last_seen_at=entity.last_seen_at,
            root_cause=entity.root_cause,
            recommended_actions=entity.recommended_actions,
            false_positive_probability=entity.false_positive_probability,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class ThreatTimelineEntryResponse(BaseModel):
    id: UUID
    incident_id: UUID
    stage: str
    description: str
    occurred_at: datetime
    source_event_id: UUID | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: ThreatTimelineEntry) -> ThreatTimelineEntryResponse:
        return cls(
            id=entity.id,
            incident_id=entity.incident_id,
            stage=entity.stage,
            description=entity.description,
            occurred_at=entity.occurred_at,
            source_event_id=entity.source_event_id,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )


class SecurityEventResponse(BaseModel):
    id: UUID
    event_type: str
    source_context: str
    account_id: UUID | None
    severity: str
    payload: dict[str, object]
    occurred_at: datetime
    processed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, entity: SecurityEvent) -> SecurityEventResponse:
        return cls(
            id=entity.id,
            event_type=entity.event_type,
            source_context=entity.source_context,
            account_id=entity.account_id,
            severity=entity.severity.value,
            payload=entity.payload,
            occurred_at=entity.occurred_at,
            processed_at=entity.processed_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
