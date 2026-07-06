from __future__ import annotations

from uuid import uuid4

import pytest

from sentinel.application.intelligence.queries import (
    GetIncidentQuery,
    ListIncidentEvidenceQuery,
    ListIncidentsQuery,
    ListIncidentTimelineQuery,
)
from sentinel.domain.intelligence.entities import Incident, ThreatTimelineEntry
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import Severity
from tests.unit.application.test_intelligence_use_cases import (
    FakeIncidentRepository,
    FakeSecurityEventRepository,
    FakeThreatTimelineEntryRepository,
    _event,
)


def _incident() -> Incident:
    now = utcnow()
    return Incident(
        title="Correlated activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=Severity.CRITICAL,
        confidence=0.9,
        first_seen_at=now,
        last_seen_at=now,
    )


async def test_list_incidents_query_delegates_to_repository() -> None:
    incidents = FakeIncidentRepository()
    incident = _incident()
    incidents.by_id[incident.id] = incident

    result = await ListIncidentsQuery(incidents).execute(limit=50, offset=0)

    assert result == [incident]


async def test_get_incident_query_returns_incident() -> None:
    incidents = FakeIncidentRepository()
    incident = _incident()
    incidents.by_id[incident.id] = incident

    result = await GetIncidentQuery(incidents).execute(incident.id)

    assert result is incident


async def test_get_incident_query_raises_for_unknown_incident() -> None:
    incidents = FakeIncidentRepository()

    with pytest.raises(EntityNotFoundError):
        await GetIncidentQuery(incidents).execute(uuid4())


async def test_list_incident_timeline_query_delegates_to_repository() -> None:
    timeline = FakeThreatTimelineEntryRepository()
    incident_id = uuid4()
    entry = ThreatTimelineEntry(
        incident_id=incident_id,
        stage="TEMP_FILE_MALICIOUS",
        description="/tmp/update_abc.php",
        occurred_at=utcnow(),
        source_event_id=None,
    )
    timeline.by_id[entry.id] = entry

    result = await ListIncidentTimelineQuery(timeline).execute(incident_id)

    assert result == [entry]


async def test_list_incident_evidence_query_resolves_source_events() -> None:
    incident_id = uuid4()
    event = _event(account_id=None)
    events = FakeSecurityEventRepository([event])
    timeline = FakeThreatTimelineEntryRepository()
    entry = ThreatTimelineEntry(
        incident_id=incident_id,
        stage="TEMP_FILE_MALICIOUS",
        description="/tmp/update_abc.php",
        occurred_at=utcnow(),
        source_event_id=event.id,
    )
    timeline.by_id[entry.id] = entry

    result = await ListIncidentEvidenceQuery(timeline, events).execute(incident_id)

    assert result == [event]


async def test_list_incident_evidence_query_skips_entries_without_source_event() -> None:
    incident_id = uuid4()
    events = FakeSecurityEventRepository()
    timeline = FakeThreatTimelineEntryRepository()
    entry = ThreatTimelineEntry(
        incident_id=incident_id,
        stage="TEMP_FILE_MALICIOUS",
        description="manual note",
        occurred_at=utcnow(),
        source_event_id=None,
    )
    timeline.by_id[entry.id] = entry

    result = await ListIncidentEvidenceQuery(timeline, events).execute(incident_id)

    assert result == []
