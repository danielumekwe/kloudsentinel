from __future__ import annotations

import builtins
import json
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.events.entities import SecurityEvent
from sentinel.domain.shared.entity import ensure_utc
from sentinel.domain.shared.value_objects import Severity
from sentinel.infrastructure.persistence.models.events import SecurityEventModel


def _event_to_entity(model: SecurityEventModel) -> SecurityEvent:
    return SecurityEvent(
        id=model.id,
        event_type=model.event_type,
        source_context=model.source_context,
        account_id=model.account_id,
        severity=Severity(model.severity),
        payload=json.loads(model.payload),
        occurred_at=ensure_utc(model.occurred_at),
        processed_at=ensure_utc(model.processed_at) if model.processed_at is not None else None,
        server_id=model.server_id,
        file_path=model.file_path,
        sha256=model.sha256,
        file_size_bytes=model.file_size_bytes,
        file_owner=model.file_owner,
        file_permissions=model.file_permissions,
        mime_type=model.mime_type,
        scanner_version=model.scanner_version,
        detection_rule_id=model.detection_rule_id,
        created_at=ensure_utc(model.created_at),
        updated_at=ensure_utc(model.updated_at),
    )


def _event_to_model(entity: SecurityEvent) -> SecurityEventModel:
    return SecurityEventModel(
        id=entity.id,
        event_type=entity.event_type,
        source_context=entity.source_context,
        account_id=entity.account_id,
        severity=entity.severity.value,
        payload=json.dumps(entity.payload),
        occurred_at=entity.occurred_at,
        processed_at=entity.processed_at,
        server_id=entity.server_id,
        file_path=entity.file_path,
        sha256=entity.sha256,
        file_size_bytes=entity.file_size_bytes,
        file_owner=entity.file_owner,
        file_permissions=entity.file_permissions,
        mime_type=entity.mime_type,
        scanner_version=entity.scanner_version,
        detection_rule_id=entity.detection_rule_id,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: SecurityEvent) -> None:
        self._session.add(_event_to_model(entity))
        await self._session.flush()

    async def save(self, entity: SecurityEvent) -> None:
        await self._session.merge(_event_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> SecurityEvent | None:
        model = await self._session.get(SecurityEventModel, entity_id)
        return _event_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[SecurityEvent]:
        result = await self._session.execute(
            select(SecurityEventModel)
            .order_by(SecurityEventModel.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_event_to_entity(model) for model in result.scalars()]

    async def list_unprocessed(self, *, limit: int = 200) -> builtins.list[SecurityEvent]:
        result = await self._session.execute(
            select(SecurityEventModel)
            .where(SecurityEventModel.processed_at.is_(None))
            .order_by(SecurityEventModel.occurred_at.asc())
            .limit(limit)
        )
        return [_event_to_entity(model) for model in result.scalars()]

    async def count_total(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(SecurityEventModel))
        return result.scalar_one()

    async def count_unprocessed(self) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(SecurityEventModel)
            .where(SecurityEventModel.processed_at.is_(None))
        )
        return result.scalar_one()

    async def list_by_account(
        self, account_id: UUID, *, limit: int = 200
    ) -> builtins.list[SecurityEvent]:
        result = await self._session.execute(
            select(SecurityEventModel)
            .where(SecurityEventModel.account_id == account_id)
            .order_by(SecurityEventModel.occurred_at.desc())
            .limit(limit)
        )
        return [_event_to_entity(model) for model in result.scalars()]
