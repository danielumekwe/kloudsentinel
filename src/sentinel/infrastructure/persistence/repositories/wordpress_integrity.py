from __future__ import annotations

import builtins
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.wordpress.integrity.entities import CoreChecksumRecord
from sentinel.infrastructure.persistence.models.wordpress_integrity import CoreChecksumRecordModel


def _to_entity(model: CoreChecksumRecordModel) -> CoreChecksumRecord:
    return CoreChecksumRecord(
        id=model.id,
        wp_version=model.wp_version,
        relative_path=model.relative_path,
        sha256=model.sha256,
        fetched_at=model.fetched_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _to_model(entity: CoreChecksumRecord) -> CoreChecksumRecordModel:
    return CoreChecksumRecordModel(
        id=entity.id,
        wp_version=entity.wp_version,
        relative_path=entity.relative_path,
        sha256=entity.sha256,
        fetched_at=entity.fetched_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyCoreChecksumRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: CoreChecksumRecord) -> None:
        self._session.add(_to_model(entity))
        await self._session.flush()

    async def save(self, entity: CoreChecksumRecord) -> None:
        await self._session.merge(_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> CoreChecksumRecord | None:
        model = await self._session.get(CoreChecksumRecordModel, entity_id)
        return _to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CoreChecksumRecord]:
        result = await self._session.execute(
            select(CoreChecksumRecordModel).limit(limit).offset(offset)
        )
        return [_to_entity(model) for model in result.scalars()]

    async def get_by_version_and_path(
        self, wp_version: str, relative_path: str
    ) -> CoreChecksumRecord | None:
        result = await self._session.execute(
            select(CoreChecksumRecordModel).where(
                CoreChecksumRecordModel.wp_version == wp_version,
                CoreChecksumRecordModel.relative_path == relative_path,
            )
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model is not None else None

    async def list_by_version(self, wp_version: str) -> builtins.list[CoreChecksumRecord]:
        result = await self._session.execute(
            select(CoreChecksumRecordModel).where(CoreChecksumRecordModel.wp_version == wp_version)
        )
        return [_to_entity(model) for model in result.scalars()]

    async def has_version(self, wp_version: str) -> bool:
        result = await self._session.execute(
            select(func.count())
            .select_from(CoreChecksumRecordModel)
            .where(CoreChecksumRecordModel.wp_version == wp_version)
        )
        return result.scalar_one() > 0
