from __future__ import annotations

from uuid import UUID

from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding, RemediationAction
from sentinel.domain.integrity.ports import (
    FileBaselineRepository,
    IntegrityFindingRepository,
    RemediationActionRepository,
)
from sentinel.domain.shared.exceptions import EntityNotFoundError


class ListFileBaselinesQuery:
    def __init__(self, baseline_repository: FileBaselineRepository) -> None:
        self._baselines = baseline_repository

    async def execute(self, *, limit: int, offset: int) -> list[FileBaseline]:
        return await self._baselines.list(limit=limit, offset=offset)


class ListIntegrityFindingsQuery:
    def __init__(self, finding_repository: IntegrityFindingRepository) -> None:
        self._findings = finding_repository

    async def execute(
        self, *, limit: int, offset: int, unacknowledged_only: bool = False
    ) -> list[IntegrityFinding]:
        if unacknowledged_only:
            return await self._findings.list_unacknowledged(limit=limit, offset=offset)
        return await self._findings.list(limit=limit, offset=offset)


class AcknowledgeIntegrityFindingUseCase:
    """Marks a finding as reviewed. Lives alongside the read queries rather
    than in ``use_cases.py`` — unlike ``RunIntegrityScanUseCase`` it's a
    single-entity mutation triggered directly by an API call, not a
    scheduled orchestration."""

    def __init__(self, finding_repository: IntegrityFindingRepository) -> None:
        self._findings = finding_repository

    async def execute(self, finding_id: UUID) -> IntegrityFinding:
        finding = await self._findings.get(finding_id)
        if finding is None:
            raise EntityNotFoundError("IntegrityFinding", finding_id)
        finding.acknowledge()
        await self._findings.save(finding)
        return finding


class ListRemediationActionsQuery:
    def __init__(self, action_repository: RemediationActionRepository) -> None:
        self._actions = action_repository

    async def execute(self, finding_id: UUID) -> list[RemediationAction]:
        return await self._actions.list_by_finding(finding_id)
