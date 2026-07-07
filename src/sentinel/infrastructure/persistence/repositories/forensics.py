from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.forensics.entities import TempFileObservation
from sentinel.domain.forensics.value_objects import ProcessContext, TempFileVerdict
from sentinel.domain.shared.entity import ensure_utc
from sentinel.domain.shared.value_objects import AbsoluteFilePath, Sha256Hash
from sentinel.infrastructure.persistence.models.forensics import TempFileObservationModel


def _process_to_json(process: ProcessContext | None) -> str | None:
    if process is None:
        return None
    return json.dumps(
        {
            "pid": process.pid,
            "ppid": process.ppid,
            "executable_path": process.executable_path,
            "command_line": process.command_line,
            "open_files": list(process.open_files),
            "network_connections": list(process.network_connections),
        }
    )


def _process_from_json(raw: str | None) -> ProcessContext | None:
    if raw is None:
        return None
    data = json.loads(raw)
    return ProcessContext(
        pid=data["pid"],
        ppid=data["ppid"],
        executable_path=data["executable_path"],
        command_line=data["command_line"],
        open_files=tuple(data["open_files"]),
        network_connections=tuple(data["network_connections"]),
    )


def _observation_to_entity(model: TempFileObservationModel) -> TempFileObservation:
    return TempFileObservation(
        id=model.id,
        absolute_path=AbsoluteFilePath(value=model.absolute_path),
        sha256=Sha256Hash(value=model.sha256) if model.sha256 is not None else None,
        owner=model.owner,
        size_bytes=model.size_bytes,
        verdict=TempFileVerdict(model.verdict),
        verdict_reason=model.verdict_reason,
        matched_rule_ids=tuple(json.loads(model.matched_rule_ids)),
        process=_process_from_json(model.process_context),
        account_id=model.account_id,
        detected_at=ensure_utc(model.detected_at),
        file_permissions=model.file_permissions,
        mime_type=model.mime_type,
        server_id=model.server_id,
        created_at=ensure_utc(model.created_at),
        updated_at=ensure_utc(model.updated_at),
    )


def _observation_to_model(entity: TempFileObservation) -> TempFileObservationModel:
    return TempFileObservationModel(
        id=entity.id,
        absolute_path=str(entity.absolute_path),
        sha256=str(entity.sha256) if entity.sha256 is not None else None,
        owner=entity.owner,
        size_bytes=entity.size_bytes,
        verdict=entity.verdict.value,
        verdict_reason=entity.verdict_reason,
        matched_rule_ids=json.dumps(list(entity.matched_rule_ids)),
        process_context=_process_to_json(entity.process),
        account_id=entity.account_id,
        detected_at=entity.detected_at,
        file_permissions=entity.file_permissions,
        mime_type=entity.mime_type,
        server_id=entity.server_id,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyTempFileObservationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: TempFileObservation) -> None:
        self._session.add(_observation_to_model(entity))
        await self._session.flush()

    async def save(self, entity: TempFileObservation) -> None:
        await self._session.merge(_observation_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> TempFileObservation | None:
        model = await self._session.get(TempFileObservationModel, entity_id)
        return _observation_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[TempFileObservation]:
        result = await self._session.execute(
            select(TempFileObservationModel)
            .order_by(TempFileObservationModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_observation_to_entity(model) for model in result.scalars()]

    async def get_by_path(self, absolute_path: str) -> TempFileObservation | None:
        result = await self._session.execute(
            select(TempFileObservationModel).where(
                TempFileObservationModel.absolute_path == absolute_path
            )
        )
        model = result.scalar_one_or_none()
        return _observation_to_entity(model) if model is not None else None

    async def count_by_verdict(self, verdict: TempFileVerdict) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(TempFileObservationModel)
            .where(TempFileObservationModel.verdict == verdict.value)
        )
        return result.scalar_one()
