from __future__ import annotations

from uuid import uuid4

import pytest

from sentinel.application.integrity.queries import (
    AcknowledgeIntegrityFindingUseCase,
    ListFileBaselinesQuery,
    ListIntegrityFindingsQuery,
)
from sentinel.domain.integrity.entities import IntegrityFinding
from sentinel.domain.integrity.value_objects import ChangeType
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash
from tests.unit.application.test_integrity_use_cases import (
    FakeFileBaselineRepository,
    FakeIntegrityFindingRepository,
)


def _finding(*, is_acknowledged: bool = False) -> IntegrityFinding:
    return IntegrityFinding(
        account_id=uuid4(),
        relative_path=RelativeFilePath(value="public_html/index.php"),
        change_type=ChangeType.MODIFIED,
        severity=Severity.HIGH,
        previous_sha256=Sha256Hash(value="a" * 64),
        current_sha256=Sha256Hash(value="b" * 64),
        detected_at=utcnow(),
        is_acknowledged=is_acknowledged,
    )


async def test_list_file_baselines_query_delegates_to_repository() -> None:
    baselines = FakeFileBaselineRepository()
    query = ListFileBaselinesQuery(baselines)

    result = await query.execute(limit=50, offset=0)

    assert result == []


async def test_list_integrity_findings_query_defaults_to_full_list() -> None:
    findings = FakeIntegrityFindingRepository()
    acknowledged = _finding(is_acknowledged=True)
    await findings.add(acknowledged)
    query = ListIntegrityFindingsQuery(findings)

    result = await query.execute(limit=50, offset=0)

    assert result == [acknowledged]


async def test_list_integrity_findings_query_unacknowledged_only_filters() -> None:
    findings = FakeIntegrityFindingRepository()
    await findings.add(_finding(is_acknowledged=True))
    unacknowledged = _finding(is_acknowledged=False)
    await findings.add(unacknowledged)
    query = ListIntegrityFindingsQuery(findings)

    result = await query.execute(limit=50, offset=0, unacknowledged_only=True)

    assert result == [unacknowledged]


async def test_acknowledge_use_case_marks_finding_acknowledged() -> None:
    findings = FakeIntegrityFindingRepository()
    finding = _finding(is_acknowledged=False)
    await findings.add(finding)
    use_case = AcknowledgeIntegrityFindingUseCase(findings)

    result = await use_case.execute(finding.id)

    assert result.is_acknowledged is True
    assert findings.by_id[finding.id].is_acknowledged is True


async def test_acknowledge_use_case_raises_for_unknown_finding() -> None:
    findings = FakeIntegrityFindingRepository()
    use_case = AcknowledgeIntegrityFindingUseCase(findings)

    with pytest.raises(EntityNotFoundError):
        await use_case.execute(uuid4())
