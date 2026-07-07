from __future__ import annotations

import builtins
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.wordpress.inventory.entities import WordPressCronJob
from sentinel.infrastructure.persistence.models.wordpress_inventory import WordPressCronJobModel


def _to_entity(model: WordPressCronJobModel) -> WordPressCronJob:
    return WordPressCronJob(
        id=model.id,
        installation_id=model.installation_id,
        command=model.command,
        schedule_raw=model.schedule_raw,
        is_suspicious=model.is_suspicious,
        flag_reason=model.flag_reason,
        is_present=model.is_present,
        last_seen_at=model.last_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _to_model(entity: WordPressCronJob) -> WordPressCronJobModel:
    return WordPressCronJobModel(
        id=entity.id,
        installation_id=entity.installation_id,
        command=entity.command,
        schedule_raw=entity.schedule_raw,
        is_suspicious=entity.is_suspicious,
        flag_reason=entity.flag_reason,
        is_present=entity.is_present,
        last_seen_at=entity.last_seen_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyWordPressCronJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: WordPressCronJob) -> None:
        self._session.add(_to_model(entity))
        await self._session.flush()

    async def save(self, entity: WordPressCronJob) -> None:
        await self._session.merge(_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> WordPressCronJob | None:
        model = await self._session.get(WordPressCronJobModel, entity_id)
        return _to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressCronJob]:
        result = await self._session.execute(
            select(WordPressCronJobModel).limit(limit).offset(offset)
        )
        return [_to_entity(model) for model in result.scalars()]

    async def list_by_installation(self, installation_id: UUID) -> builtins.list[WordPressCronJob]:
        result = await self._session.execute(
            select(WordPressCronJobModel).where(
                WordPressCronJobModel.installation_id == installation_id
            )
        )
        return [_to_entity(model) for model in result.scalars()]

    async def get_by_installation_and_command(
        self, installation_id: UUID, command: str
    ) -> WordPressCronJob | None:
        result = await self._session.execute(
            select(WordPressCronJobModel).where(
                WordPressCronJobModel.installation_id == installation_id,
                WordPressCronJobModel.command == command,
            )
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model is not None else None
