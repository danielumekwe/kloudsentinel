from __future__ import annotations

import builtins
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.monitoring.entities import ConfigurationItem
from sentinel.infrastructure.persistence.models.monitoring import ConfigurationItemModel


def _to_entity(model: ConfigurationItemModel) -> ConfigurationItem:
    return ConfigurationItem(
        id=model.id,
        installation_id=model.installation_id,
        config_source=model.config_source,
        key=model.key,
        raw_value=model.raw_value,
        is_flagged=model.is_flagged,
        flag_reason=model.flag_reason,
        is_present=model.is_present,
        last_seen_at=model.last_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _to_model(entity: ConfigurationItem) -> ConfigurationItemModel:
    return ConfigurationItemModel(
        id=entity.id,
        installation_id=entity.installation_id,
        config_source=entity.config_source,
        key=entity.key,
        raw_value=entity.raw_value,
        is_flagged=entity.is_flagged,
        flag_reason=entity.flag_reason,
        is_present=entity.is_present,
        last_seen_at=entity.last_seen_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyConfigurationItemRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: ConfigurationItem) -> None:
        self._session.add(_to_model(entity))
        await self._session.flush()

    async def save(self, entity: ConfigurationItem) -> None:
        await self._session.merge(_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> ConfigurationItem | None:
        model = await self._session.get(ConfigurationItemModel, entity_id)
        return _to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[ConfigurationItem]:
        result = await self._session.execute(
            select(ConfigurationItemModel).limit(limit).offset(offset)
        )
        return [_to_entity(m) for m in result.scalars()]

    async def get_by_installation_source_and_key(
        self, installation_id: UUID, config_source: str, key: str
    ) -> ConfigurationItem | None:
        result = await self._session.execute(
            select(ConfigurationItemModel).where(
                ConfigurationItemModel.installation_id == installation_id,
                ConfigurationItemModel.config_source == config_source,
                ConfigurationItemModel.key == key,
            )
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model is not None else None

    async def list_by_installation(self, installation_id: UUID) -> builtins.list[ConfigurationItem]:
        result = await self._session.execute(
            select(ConfigurationItemModel).where(
                ConfigurationItemModel.installation_id == installation_id
            )
        )
        return [_to_entity(m) for m in result.scalars()]
