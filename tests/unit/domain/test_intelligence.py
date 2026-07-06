from __future__ import annotations

from sentinel.domain.intelligence.entities import Incident
from sentinel.domain.intelligence.value_objects import IncidentStatus, RootCauseConclusion
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.value_objects import Severity


def _incident(*, severity: Severity = Severity.MEDIUM, confidence: float = 0.5) -> Incident:
    now = utcnow()
    return Incident(
        title="Correlated temp_file_malicious activity",
        correlation_signature="temp_file_malicious:webshell-signature",
        severity=severity,
        confidence=confidence,
        first_seen_at=now,
        last_seen_at=now,
    )


def test_new_incident_defaults_to_open() -> None:
    incident = _incident()

    assert incident.status is IncidentStatus.OPEN
    assert incident.root_cause is None


def test_record_new_evidence_bumps_confidence_and_last_seen() -> None:
    incident = _incident(confidence=0.5)
    at = utcnow()

    incident.record_new_evidence(at=at, confidence=0.8, severity=Severity.MEDIUM)

    assert incident.confidence == 0.8
    assert incident.last_seen_at == at


def test_record_new_evidence_escalates_severity_but_never_downgrades() -> None:
    incident = _incident(severity=Severity.MEDIUM)

    incident.record_new_evidence(at=utcnow(), confidence=0.6, severity=Severity.CRITICAL)
    assert incident.severity is Severity.CRITICAL

    incident.record_new_evidence(at=utcnow(), confidence=0.7, severity=Severity.LOW)
    assert incident.severity is Severity.CRITICAL


def test_apply_root_cause_populates_fields_from_conclusion() -> None:
    incident = _incident(confidence=0.6)
    conclusion = RootCauseConclusion(
        confidence=0.9,
        summary="Shared plugin elementor (3.4) across all 6 affected accounts",
        evidence=("elementor 3.4 present on every affected account",),
        reasoning="All 6 accounts share plugin 'elementor' version '3.4'",
        recommended_action="Update or remove plugin 'elementor' on all affected accounts",
        false_positive_probability=0.1,
    )

    incident.apply_root_cause(conclusion)

    assert incident.root_cause == conclusion.summary
    assert incident.recommended_actions == conclusion.recommended_action
    assert incident.false_positive_probability == 0.1
    assert incident.confidence == 0.9


def test_apply_root_cause_never_lowers_existing_confidence() -> None:
    incident = _incident(confidence=0.95)
    conclusion = RootCauseConclusion(
        confidence=0.6,
        summary="Ambiguous shared plugin",
        evidence=(),
        reasoning="Multiple shared plugins found",
        recommended_action="Investigate further",
        false_positive_probability=0.4,
    )

    incident.apply_root_cause(conclusion)

    assert incident.confidence == 0.95


def test_mark_status_updates_status() -> None:
    incident = _incident()

    incident.mark_status(IncidentStatus.RESOLVED)

    assert incident.status is IncidentStatus.RESOLVED
