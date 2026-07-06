from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.shared.entity import ValueObject
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity


@dataclass(frozen=True, kw_only=True)
class HeuristicMatch(ValueObject):
    """One signature/heuristic hit produced by a ``HeuristicScanner`` against
    a file with no prior baseline to diff against — unlike
    ``domain.integrity``'s findings, which describe a *change*, this
    describes a suspicious *pattern* observed in a single, one-off scan."""

    relative_path: RelativeFilePath
    rule_id: str
    description: str
    severity: Severity
    line_number: int | None
    snippet: str
