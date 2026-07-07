from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinel.domain.heuristics.ports import HeuristicScanner
from sentinel.domain.heuristics.value_objects import HeuristicMatch
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import FileRemediationError
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity
from sentinel.infrastructure.filesystem.local_file_remediator import LocalFileRemediator


@dataclass(frozen=True)
class ArchiveScanResult:
    root: str
    affected_files: int
    findings: list[HeuristicMatch]


class ScanArchiveUseCase:
    """Runs a signature/heuristic scan over an arbitrary local directory with
    no prior baseline — see ``HeuristicScanner`` for why this is a distinct
    detection strategy from ``RunIntegrityScanUseCase``'s hash diffing."""

    def __init__(self, *, scanner: HeuristicScanner) -> None:
        self._scanner = scanner

    async def execute(self, root: Path) -> ArchiveScanResult:
        findings = await self._scanner.scan(root)
        findings.sort(key=lambda match: match.severity.rank, reverse=True)
        affected_files = len({str(match.relative_path) for match in findings})
        return ArchiveScanResult(root=str(root), affected_files=affected_files, findings=findings)


@dataclass(frozen=True)
class QuarantineAttempt:
    relative_path: str
    succeeded: bool
    detail: str
    """Quarantine path on success, error message on failure."""


class QuarantineArchiveFindingsUseCase:
    """Quarantines every distinct file behind a finding at or above
    ``min_severity``. Tolerates and records individual failures rather than
    aborting the whole run — one locked or permission-denied file shouldn't
    stop the rest of a batch from being quarantined."""

    def __init__(self, *, remediator: LocalFileRemediator) -> None:
        self._remediator = remediator

    async def execute(
        self, findings: list[HeuristicMatch], *, min_severity: Severity
    ) -> list[QuarantineAttempt]:
        # ``findings`` arrives sorted by severity descending (see
        # ``ScanArchiveUseCase.execute``), so the first match kept per path
        # via ``setdefault`` is that path's highest-severity match — the one
        # worth recording as the quarantine's detection reason.
        matches_by_path: dict[str, HeuristicMatch] = {}
        for match in findings:
            if match.severity.rank >= min_severity.rank:
                matches_by_path.setdefault(str(match.relative_path), match)

        attempts: list[QuarantineAttempt] = []
        for relative_path in sorted(matches_by_path):
            match = matches_by_path[relative_path]
            try:
                quarantined = await self._remediator.quarantine(
                    relative_path=RelativeFilePath(value=relative_path),
                    detection_reason=f"{match.rule_id}: {match.description}",
                    severity=match.severity,
                    detected_at=utcnow(),
                )
            except FileRemediationError as exc:
                attempts.append(
                    QuarantineAttempt(relative_path=relative_path, succeeded=False, detail=str(exc))
                )
                continue

            attempts.append(
                QuarantineAttempt(
                    relative_path=relative_path,
                    succeeded=True,
                    detail=quarantined.quarantine_path,
                )
            )
        return attempts
