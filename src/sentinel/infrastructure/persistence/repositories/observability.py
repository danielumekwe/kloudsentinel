from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.observability.entities import JobHeartbeat
from sentinel.domain.observability.value_objects import JobHeartbeatStatus
from sentinel.domain.shared.entity import ensure_utc
from sentinel.infrastructure.persistence.models.observability import JobHeartbeatModel


def _to_entity(model: JobHeartbeatModel) -> JobHeartbeat:
    return JobHeartbeat(
        id=model.id,
        job_id=model.job_id,
        status=JobHeartbeatStatus(model.status),
        last_run_at=ensure_utc(model.last_run_at),
        last_duration_ms=model.last_duration_ms,
        last_error=model.last_error,
        created_at=ensure_utc(model.created_at),
        updated_at=ensure_utc(model.updated_at),
    )


def _to_model(entity: JobHeartbeat) -> JobHeartbeatModel:
    return JobHeartbeatModel(
        id=entity.id,
        job_id=entity.job_id,
        status=entity.status.value,
        last_run_at=entity.last_run_at,
        last_duration_ms=entity.last_duration_ms,
        last_error=entity.last_error,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyJobHeartbeatRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: JobHeartbeat) -> None:
        self._session.add(_to_model(entity))
        await self._session.flush()

    async def save(self, entity: JobHeartbeat) -> None:
        await self._session.merge(_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> JobHeartbeat | None:
        model = await self._session.get(JobHeartbeatModel, entity_id)
        return _to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[JobHeartbeat]:
        result = await self._session.execute(select(JobHeartbeatModel).limit(limit).offset(offset))
        return [_to_entity(model) for model in result.scalars()]

    async def find_by_job_id(self, job_id: str) -> JobHeartbeat | None:
        result = await self._session.execute(
            select(JobHeartbeatModel).where(JobHeartbeatModel.job_id == job_id)
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model is not None else None
