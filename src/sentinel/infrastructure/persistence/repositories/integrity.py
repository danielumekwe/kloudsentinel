from __future__ import annotations

import builtins
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.integrity.entities import FileBaseline, IntegrityFinding, RemediationAction
from sentinel.domain.integrity.value_objects import (
    ChangeType,
    RemediationActionType,
    RemediationOutcome,
    RemediationState,
)
from sentinel.domain.shared.value_objects import RelativeFilePath, Severity, Sha256Hash
from sentinel.infrastructure.persistence.models.integrity import (
    FileBaselineModel,
    IntegrityFindingModel,
    RemediationActionModel,
)


def _baseline_to_entity(model: FileBaselineModel) -> FileBaseline:
    return FileBaseline(
        id=model.id,
        account_id=model.account_id,
        relative_path=RelativeFilePath(value=model.relative_path),
        sha256=Sha256Hash(value=model.sha256),
        size_bytes=model.size_bytes,
        mode=model.mode,
        is_active=model.is_active,
        last_verified_at=model.last_verified_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _baseline_to_model(entity: FileBaseline) -> FileBaselineModel:
    return FileBaselineModel(
        id=entity.id,
        account_id=entity.account_id,
        relative_path=str(entity.relative_path),
        sha256=str(entity.sha256),
        size_bytes=entity.size_bytes,
        mode=entity.mode,
        is_active=entity.is_active,
        last_verified_at=entity.last_verified_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyFileBaselineRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: FileBaseline) -> None:
        self._session.add(_baseline_to_model(entity))
        await self._session.flush()

    async def save(self, entity: FileBaseline) -> None:
        await self._session.merge(_baseline_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> FileBaseline | None:
        model = await self._session.get(FileBaselineModel, entity_id)
        return _baseline_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[FileBaseline]:
        result = await self._session.execute(select(FileBaselineModel).limit(limit).offset(offset))
        return [_baseline_to_entity(model) for model in result.scalars()]

    async def get_by_account_and_path(
        self, account_id: UUID, relative_path: RelativeFilePath
    ) -> FileBaseline | None:
        result = await self._session.execute(
            select(FileBaselineModel).where(
                FileBaselineModel.account_id == account_id,
                FileBaselineModel.relative_path == str(relative_path),
            )
        )
        model = result.scalar_one_or_none()
        return _baseline_to_entity(model) if model is not None else None

    async def list_by_account(self, account_id: UUID) -> builtins.list[FileBaseline]:
        result = await self._session.execute(
            select(FileBaselineModel).where(FileBaselineModel.account_id == account_id)
        )
        return [_baseline_to_entity(model) for model in result.scalars()]


def _finding_to_entity(model: IntegrityFindingModel) -> IntegrityFinding:
    return IntegrityFinding(
        id=model.id,
        account_id=model.account_id,
        relative_path=RelativeFilePath(value=model.relative_path),
        change_type=ChangeType(model.change_type),
        severity=Severity(model.severity),
        previous_sha256=(
            Sha256Hash(value=model.previous_sha256) if model.previous_sha256 is not None else None
        ),
        current_sha256=(
            Sha256Hash(value=model.current_sha256) if model.current_sha256 is not None else None
        ),
        is_acknowledged=model.is_acknowledged,
        remediation_state=RemediationState(model.remediation_state),
        quarantine_path=model.quarantine_path,
        quarantine_mode=model.quarantine_mode,
        quarantine_size_bytes=model.quarantine_size_bytes,
        detected_at=model.detected_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _finding_to_model(entity: IntegrityFinding) -> IntegrityFindingModel:
    return IntegrityFindingModel(
        id=entity.id,
        account_id=entity.account_id,
        relative_path=str(entity.relative_path),
        change_type=entity.change_type.value,
        severity=entity.severity.value,
        previous_sha256=(
            str(entity.previous_sha256) if entity.previous_sha256 is not None else None
        ),
        current_sha256=str(entity.current_sha256) if entity.current_sha256 is not None else None,
        is_acknowledged=entity.is_acknowledged,
        remediation_state=entity.remediation_state.value,
        quarantine_path=entity.quarantine_path,
        quarantine_mode=entity.quarantine_mode,
        quarantine_size_bytes=entity.quarantine_size_bytes,
        detected_at=entity.detected_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyIntegrityFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: IntegrityFinding) -> None:
        self._session.add(_finding_to_model(entity))
        await self._session.flush()

    async def save(self, entity: IntegrityFinding) -> None:
        await self._session.merge(_finding_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> IntegrityFinding | None:
        model = await self._session.get(IntegrityFindingModel, entity_id)
        return _finding_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[IntegrityFinding]:
        result = await self._session.execute(
            select(IntegrityFindingModel)
            .order_by(IntegrityFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_finding_to_entity(model) for model in result.scalars()]

    async def list_unacknowledged(
        self, *, limit: int = 50, offset: int = 0
    ) -> builtins.list[IntegrityFinding]:
        result = await self._session.execute(
            select(IntegrityFindingModel)
            .where(IntegrityFindingModel.is_acknowledged.is_(False))
            .order_by(IntegrityFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_finding_to_entity(model) for model in result.scalars()]


def _action_to_entity(model: RemediationActionModel) -> RemediationAction:
    return RemediationAction(
        id=model.id,
        finding_id=model.finding_id,
        account_id=model.account_id,
        relative_path=RelativeFilePath(value=model.relative_path),
        action_type=RemediationActionType(model.action_type),
        outcome=RemediationOutcome(model.outcome),
        detail=model.detail,
        performed_at=model.performed_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _action_to_model(entity: RemediationAction) -> RemediationActionModel:
    return RemediationActionModel(
        id=entity.id,
        finding_id=entity.finding_id,
        account_id=entity.account_id,
        relative_path=str(entity.relative_path),
        action_type=entity.action_type.value,
        outcome=entity.outcome.value,
        detail=entity.detail,
        performed_at=entity.performed_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyRemediationActionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: RemediationAction) -> None:
        self._session.add(_action_to_model(entity))
        await self._session.flush()

    async def save(self, entity: RemediationAction) -> None:
        await self._session.merge(_action_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> RemediationAction | None:
        model = await self._session.get(RemediationActionModel, entity_id)
        return _action_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> builtins.list[RemediationAction]:
        result = await self._session.execute(
            select(RemediationActionModel)
            .order_by(RemediationActionModel.performed_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_action_to_entity(model) for model in result.scalars()]

    async def list_by_finding(self, finding_id: UUID) -> builtins.list[RemediationAction]:
        result = await self._session.execute(
            select(RemediationActionModel)
            .where(RemediationActionModel.finding_id == finding_id)
            .order_by(RemediationActionModel.performed_at.desc())
        )
        return [_action_to_entity(model) for model in result.scalars()]
