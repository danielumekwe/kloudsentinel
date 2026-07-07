from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.shared.entity import ValueObject
from sentinel.domain.shared.value_objects import Severity


@dataclass(frozen=True, kw_only=True)
class WordPressForensicFinding(ValueObject):
    """One WordPress-structural or persistence-mechanism finding — distinct
    from a generic ``IntegrityFinding`` (a file changed) or malware-content
    match (a rule fired): these are things only WordPress's own conventions
    make suspicious, like a plugin directory with no valid header or a
    must-use plugin nobody remembers installing."""

    finding_type: str
    relative_path: str
    description: str
    severity: Severity
    matched_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    sha256: str | None = None
    """Populated only when a malware-content match was found (i.e. the
    scanner already read the file's bytes to check it) — lets a CRITICAL
    finding be turned into a quarantinable ``IntegrityFinding`` without
    the application layer re-reading the file itself."""
