from __future__ import annotations

import builtins
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.discovery.entities import CpanelAccount, Server, WordPressInstallation
from sentinel.domain.discovery.value_objects import LinuxUsername
from sentinel.domain.shared.value_objects import AbsoluteFilePath, DomainName
from sentinel.infrastructure.persistence.models.discovery import (
    CpanelAccountModel,
    ServerModel,
    WordPressInstallationModel,
)


def _server_to_entity(model: ServerModel) -> Server:
    return Server(
        id=model.id,
        hostname=model.hostname,
        os_info=model.os_info,
        agent_version=model.agent_version,
        last_seen_at=model.last_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _server_to_model(entity: Server) -> ServerModel:
    return ServerModel(
        id=entity.id,
        hostname=entity.hostname,
        os_info=entity.os_info,
        agent_version=entity.agent_version,
        last_seen_at=entity.last_seen_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyServerRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: Server) -> None:
        self._session.add(_server_to_model(entity))
        await self._session.flush()

    async def save(self, entity: Server) -> None:
        await self._session.merge(_server_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> Server | None:
        model = await self._session.get(ServerModel, entity_id)
        return _server_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[Server]:
        result = await self._session.execute(select(ServerModel).limit(limit).offset(offset))
        return [_server_to_entity(model) for model in result.scalars()]

    async def get_by_hostname(self, hostname: str) -> Server | None:
        result = await self._session.execute(
            select(ServerModel).where(ServerModel.hostname == hostname)
        )
        model = result.scalar_one_or_none()
        return _server_to_entity(model) if model is not None else None


def _account_to_entity(model: CpanelAccountModel) -> CpanelAccount:
    return CpanelAccount(
        id=model.id,
        server_id=model.server_id,
        username=LinuxUsername(value=model.username),
        primary_domain=DomainName(value=model.primary_domain),
        home_directory=AbsoluteFilePath(value=model.home_directory),
        is_suspended=model.is_suspended,
        is_active=model.is_active,
        last_seen_at=model.last_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _account_to_model(entity: CpanelAccount) -> CpanelAccountModel:
    return CpanelAccountModel(
        id=entity.id,
        server_id=entity.server_id,
        username=str(entity.username),
        primary_domain=str(entity.primary_domain),
        home_directory=str(entity.home_directory),
        is_suspended=entity.is_suspended,
        is_active=entity.is_active,
        last_seen_at=entity.last_seen_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyCpanelAccountRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: CpanelAccount) -> None:
        self._session.add(_account_to_model(entity))
        await self._session.flush()

    async def save(self, entity: CpanelAccount) -> None:
        await self._session.merge(_account_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> CpanelAccount | None:
        model = await self._session.get(CpanelAccountModel, entity_id)
        return _account_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[CpanelAccount]:
        result = await self._session.execute(select(CpanelAccountModel).limit(limit).offset(offset))
        return [_account_to_entity(model) for model in result.scalars()]

    async def get_by_username(self, username: LinuxUsername) -> CpanelAccount | None:
        result = await self._session.execute(
            select(CpanelAccountModel).where(CpanelAccountModel.username == str(username))
        )
        model = result.scalar_one_or_none()
        return _account_to_entity(model) if model is not None else None

    async def list_by_server(self, server_id: UUID) -> builtins.list[CpanelAccount]:
        result = await self._session.execute(
            select(CpanelAccountModel).where(CpanelAccountModel.server_id == server_id)
        )
        return [_account_to_entity(model) for model in result.scalars()]


def _installation_to_entity(model: WordPressInstallationModel) -> WordPressInstallation:
    return WordPressInstallation(
        id=model.id,
        cpanel_account_id=model.cpanel_account_id,
        absolute_path=AbsoluteFilePath(value=model.absolute_path),
        domain=DomainName(value=model.domain) if model.domain is not None else None,
        wp_version=model.wp_version,
        is_multisite=model.is_multisite,
        is_active=model.is_active,
        last_seen_at=model.last_seen_at,
        php_version=model.php_version,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _installation_to_model(entity: WordPressInstallation) -> WordPressInstallationModel:
    return WordPressInstallationModel(
        id=entity.id,
        cpanel_account_id=entity.cpanel_account_id,
        absolute_path=str(entity.absolute_path),
        domain=str(entity.domain) if entity.domain is not None else None,
        wp_version=entity.wp_version,
        is_multisite=entity.is_multisite,
        is_active=entity.is_active,
        last_seen_at=entity.last_seen_at,
        php_version=entity.php_version,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyWordPressInstallationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: WordPressInstallation) -> None:
        self._session.add(_installation_to_model(entity))
        await self._session.flush()

    async def save(self, entity: WordPressInstallation) -> None:
        await self._session.merge(_installation_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> WordPressInstallation | None:
        model = await self._session.get(WordPressInstallationModel, entity_id)
        return _installation_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[WordPressInstallation]:
        result = await self._session.execute(
            select(WordPressInstallationModel).limit(limit).offset(offset)
        )
        return [_installation_to_entity(model) for model in result.scalars()]

    async def get_by_path(self, absolute_path: str) -> WordPressInstallation | None:
        result = await self._session.execute(
            select(WordPressInstallationModel).where(
                WordPressInstallationModel.absolute_path == absolute_path
            )
        )
        model = result.scalar_one_or_none()
        return _installation_to_entity(model) if model is not None else None

    async def list_by_account(
        self, cpanel_account_id: UUID
    ) -> builtins.list[WordPressInstallation]:
        result = await self._session.execute(
            select(WordPressInstallationModel).where(
                WordPressInstallationModel.cpanel_account_id == cpanel_account_id
            )
        )
        return [_installation_to_entity(model) for model in result.scalars()]
