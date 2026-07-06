from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sentinel.domain.shared.entity import ValueObject


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True, kw_only=True)
class RootCauseConclusion(ValueObject):
    """A deterministic, rule-based conclusion about why an incident
    happened — never an opaque ML/LLM output. Every field here is populated
    by ``AnalyzeRootCauseUseCase``'s explicit formula over evidence already
    in the database, so a conclusion can always be traced back to the exact
    data that produced it.
    """

    confidence: float
    summary: str
    evidence: tuple[str, ...]
    reasoning: str
    recommended_action: str
    false_positive_probability: float
