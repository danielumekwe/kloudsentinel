from __future__ import annotations

import builtins
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.inventory.entities import InstalledPlugin, InstalledTheme
from sentinel.infrastructure.persistence.models.inventory import (
    InstalledPluginModel,
    InstalledThemeModel,
)


def _plugin_to_entity(model: InstalledPluginModel) -> InstalledPlugin:
    return InstalledPlugin(
        id=model.id,
        installation_id=model.installation_id,
        slug=model.slug,
        name=model.name,
        version=model.version,
        is_present=model.is_present,
        last_seen_at=model.last_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _plugin_to_model(entity: InstalledPlugin) -> InstalledPluginModel:
    return InstalledPluginModel(
        id=entity.id,
        installation_id=entity.installation_id,
        slug=entity.slug,
        name=entity.name,
        version=entity.version,
        is_present=entity.is_present,
        last_seen_at=entity.last_seen_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyInstalledPluginRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: InstalledPlugin) -> None:
        self._session.add(_plugin_to_model(entity))
        await self._session.flush()

    async def save(self, entity: InstalledPlugin) -> None:
        await self._session.merge(_plugin_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> InstalledPlugin | None:
        model = await self._session.get(InstalledPluginModel, entity_id)
        return _plugin_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledPlugin]:
        result = await self._session.execute(
            select(InstalledPluginModel).limit(limit).offset(offset)
        )
        return [_plugin_to_entity(model) for model in result.scalars()]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledPlugin | None:
        result = await self._session.execute(
            select(InstalledPluginModel).where(
                InstalledPluginModel.installation_id == installation_id,
                InstalledPluginModel.slug == slug,
            )
        )
        model = result.scalar_one_or_none()
        return _plugin_to_entity(model) if model is not None else None

    async def list_by_installation(self, installation_id: UUID) -> builtins.list[InstalledPlugin]:
        result = await self._session.execute(
            select(InstalledPluginModel).where(
                InstalledPluginModel.installation_id == installation_id
            )
        )
        return [_plugin_to_entity(model) for model in result.scalars()]


def _theme_to_entity(model: InstalledThemeModel) -> InstalledTheme:
    return InstalledTheme(
        id=model.id,
        installation_id=model.installation_id,
        slug=model.slug,
        name=model.name,
        version=model.version,
        is_present=model.is_present,
        last_seen_at=model.last_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _theme_to_model(entity: InstalledTheme) -> InstalledThemeModel:
    return InstalledThemeModel(
        id=entity.id,
        installation_id=entity.installation_id,
        slug=entity.slug,
        name=entity.name,
        version=entity.version,
        is_present=entity.is_present,
        last_seen_at=entity.last_seen_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyInstalledThemeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: InstalledTheme) -> None:
        self._session.add(_theme_to_model(entity))
        await self._session.flush()

    async def save(self, entity: InstalledTheme) -> None:
        await self._session.merge(_theme_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> InstalledTheme | None:
        model = await self._session.get(InstalledThemeModel, entity_id)
        return _theme_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[InstalledTheme]:
        result = await self._session.execute(
            select(InstalledThemeModel).limit(limit).offset(offset)
        )
        return [_theme_to_entity(model) for model in result.scalars()]

    async def get_by_installation_and_slug(
        self, installation_id: UUID, slug: str
    ) -> InstalledTheme | None:
        result = await self._session.execute(
            select(InstalledThemeModel).where(
                InstalledThemeModel.installation_id == installation_id,
                InstalledThemeModel.slug == slug,
            )
        )
        model = result.scalar_one_or_none()
        return _theme_to_entity(model) if model is not None else None

    async def list_by_installation(self, installation_id: UUID) -> builtins.list[InstalledTheme]:
        result = await self._session.execute(
            select(InstalledThemeModel).where(
                InstalledThemeModel.installation_id == installation_id
            )
        )
        return [_theme_to_entity(model) for model in result.scalars()]
