from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sentinel.application.heuristics.use_cases import (
    QuarantineArchiveFindingsUseCase,
    ScanArchiveUseCase,
)
from sentinel.domain.heuristics.value_objects import HeuristicMatch
from sentinel.domain.integrity.value_objects import QuarantinedFile
from sentinel.domain.shared.exceptions import FileRemediationError
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity


def _match(path: str, *, severity: Severity, rule_id: str = "rule") -> HeuristicMatch:
    return HeuristicMatch(
        relative_path=RelativeFilePath(value=path),
        rule_id=rule_id,
        description="test finding",
        severity=severity,
        line_number=1,
        snippet="snippet",
    )


class FakeHeuristicScanner:
    def __init__(self, matches: list[HeuristicMatch]) -> None:
        self._matches = matches

    async def scan(self, root: Path) -> list[HeuristicMatch]:
        return list(self._matches)


class FakeLocalFileRemediator:
    def __init__(self, *, fail_paths: set[str] | None = None) -> None:
        self._fail_paths = fail_paths or set()
        self.quarantined_paths: list[str] = []

    async def quarantine(
        self,
        *,
        relative_path: RelativeFilePath,
        detection_reason: str,
        severity: Severity,
        detected_at: datetime,
    ) -> QuarantinedFile:
        path = str(relative_path)
        if path in self._fail_paths:
            raise FileRemediationError(f"simulated failure for {path}")
        self.quarantined_paths.append(path)
        return QuarantinedFile(
            quarantine_path=f"/quarantine/{path}",
            mode="644",
            size_bytes=10,
            owner_uid=1000,
            owner_gid=1000,
        )


async def test_scan_archive_sorts_findings_by_severity_descending() -> None:
    matches = [
        _match("low.php", severity=Severity.LOW),
        _match("critical.php", severity=Severity.CRITICAL),
        _match("medium.php", severity=Severity.MEDIUM),
    ]
    use_case = ScanArchiveUseCase(scanner=FakeHeuristicScanner(matches))

    result = await use_case.execute(Path("/some/archive"))

    assert [f.severity for f in result.findings] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert result.affected_files == 3
    assert result.root == "/some/archive"


async def test_scan_archive_counts_distinct_affected_files() -> None:
    matches = [
        _match("shell.php", severity=Severity.CRITICAL, rule_id="webshell-signature"),
        _match("shell.php", severity=Severity.HIGH, rule_id="long-line"),
    ]
    use_case = ScanArchiveUseCase(scanner=FakeHeuristicScanner(matches))

    result = await use_case.execute(Path("/some/archive"))

    assert result.affected_files == 1
    assert len(result.findings) == 2


async def test_quarantine_use_case_only_quarantines_files_at_or_above_threshold() -> None:
    matches = [
        _match("critical.php", severity=Severity.CRITICAL),
        _match("low.php", severity=Severity.LOW),
    ]
    remediator = FakeLocalFileRemediator()
    use_case = QuarantineArchiveFindingsUseCase(remediator=remediator)

    attempts = await use_case.execute(matches, min_severity=Severity.HIGH)

    assert remediator.quarantined_paths == ["critical.php"]
    assert len(attempts) == 1
    assert attempts[0].succeeded is True
    assert attempts[0].detail == "/quarantine/critical.php"


async def test_quarantine_use_case_deduplicates_paths_with_multiple_findings() -> None:
    matches = [
        _match("shell.php", severity=Severity.CRITICAL, rule_id="webshell-signature"),
        _match("shell.php", severity=Severity.HIGH, rule_id="long-line"),
    ]
    remediator = FakeLocalFileRemediator()
    use_case = QuarantineArchiveFindingsUseCase(remediator=remediator)

    attempts = await use_case.execute(matches, min_severity=Severity.HIGH)

    assert remediator.quarantined_paths == ["shell.php"]
    assert len(attempts) == 1


async def test_quarantine_use_case_tolerates_individual_failures() -> None:
    matches = [
        _match("broken.php", severity=Severity.CRITICAL),
        _match("ok.php", severity=Severity.CRITICAL),
    ]
    remediator = FakeLocalFileRemediator(fail_paths={"broken.php"})
    use_case = QuarantineArchiveFindingsUseCase(remediator=remediator)

    attempts = await use_case.execute(matches, min_severity=Severity.HIGH)

    by_path = {attempt.relative_path: attempt for attempt in attempts}
    assert by_path["broken.php"].succeeded is False
    assert "simulated failure" in by_path["broken.php"].detail
    assert by_path["ok.php"].succeeded is True
    assert remediator.quarantined_paths == ["ok.php"]


async def test_quarantine_use_case_returns_empty_when_nothing_qualifies() -> None:
    matches = [_match("low.php", severity=Severity.LOW)]
    remediator = FakeLocalFileRemediator()
    use_case = QuarantineArchiveFindingsUseCase(remediator=remediator)

    attempts = await use_case.execute(matches, min_severity=Severity.CRITICAL)

    assert attempts == []
    assert remediator.quarantined_paths == []
