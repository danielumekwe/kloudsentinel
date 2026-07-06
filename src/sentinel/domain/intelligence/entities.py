from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sentinel.domain.intelligence.value_objects import IncidentStatus, RootCauseConclusion
from sentinel.domain.shared.entity import BaseEntity
from sentinel.domain.shared.value_objects import Severity


@dataclass(kw_only=True)
class Incident(BaseEntity):
    """One correlated attack, grouping every ``SecurityEvent`` that shares a
    behavioral signature within the correlation time window — the answer to
    "are these six unrelated-looking /tmp/update_*.php alerts actually one
    attack?".

    ``correlation_signature`` is the internal join key ``RunCorrelationUseCase``
    uses to find an already-open incident for new matching evidence rather
    than creating a duplicate; it is not meant to be a human-facing field.
    """

    title: str
    correlation_signature: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity
    confidence: float
    first_seen_at: datetime
    last_seen_at: datetime
    root_cause: str | None = None
    recommended_actions: str | None = None
    false_positive_probability: float | None = None

    def record_new_evidence(self, *, at: datetime, confidence: float, severity: Severity) -> None:
        self.last_seen_at = max(self.last_seen_at, at)
        self.confidence = confidence
        if severity.rank > self.severity.rank:
            self.severity = severity
        self.touch()

    def apply_root_cause(self, conclusion: RootCauseConclusion) -> None:
        self.root_cause = conclusion.summary
        self.recommended_actions = conclusion.recommended_action
        self.false_positive_probability = conclusion.false_positive_probability
        self.confidence = max(self.confidence, conclusion.confidence)
        self.touch()

    def mark_status(self, status: IncidentStatus) -> None:
        self.status = status
        self.touch()


@dataclass(kw_only=True)
class IncidentAccountLink(BaseEntity):
    """One affected account attached to an incident. A plain join entity —
    deliberately no extra fields beyond identity, matching the "affected
    accounts" list from the spec's Feature 1."""

    incident_id: UUID
    account_id: UUID


@dataclass(kw_only=True)
class ThreatTimelineEntry(BaseEntity):
    """One stage in an incident's attack timeline (Feature 9), linked back
    to the ``SecurityEvent`` that evidenced it. ``stage`` is deliberately a
    free-text label rather than a closed enum — attack stages are open-ended
    and a fixed set would either be incomplete or force a bad fit."""

    incident_id: UUID
    stage: str
    description: str
    occurred_at: datetime
    source_event_id: UUID | None
