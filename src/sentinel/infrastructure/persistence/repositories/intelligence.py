from __future__ import annotations

import builtins
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.intelligence.entities import (
    Incident,
    IncidentAccountLink,
    ThreatTimelineEntry,
)
from sentinel.domain.intelligence.value_objects import IncidentStatus
from sentinel.domain.shared.entity import ensure_utc
from sentinel.domain.shared.value_objects import Severity
from sentinel.infrastructure.persistence.models.intelligence import (
    IncidentAccountLinkModel,
    IncidentModel,
    ThreatTimelineEntryModel,
)


def _incident_to_entity(model: IncidentModel) -> Incident:
    return Incident(
        id=model.id,
        title=model.title,
        correlation_signature=model.correlation_signature,
        status=IncidentStatus(model.status),
        severity=Severity(model.severity),
        confidence=model.confidence,
        first_seen_at=ensure_utc(model.first_seen_at),
        last_seen_at=ensure_utc(model.last_seen_at),
        root_cause=model.root_cause,
        recommended_actions=model.recommended_actions,
        false_positive_probability=model.false_positive_probability,
        created_at=ensure_utc(model.created_at),
        updated_at=ensure_utc(model.updated_at),
    )


def _incident_to_model(entity: Incident) -> IncidentModel:
    return IncidentModel(
        id=entity.id,
        title=entity.title,
        correlation_signature=entity.correlation_signature,
        status=entity.status.value,
        severity=entity.severity.value,
        confidence=entity.confidence,
        first_seen_at=entity.first_seen_at,
        last_seen_at=entity.last_seen_at,
        root_cause=entity.root_cause,
        recommended_actions=entity.recommended_actions,
        false_positive_probability=entity.false_positive_probability,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyIncidentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: Incident) -> None:
        self._session.add(_incident_to_model(entity))
        await self._session.flush()

    async def save(self, entity: Incident) -> None:
        await self._session.merge(_incident_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> Incident | None:
        model = await self._session.get(IncidentModel, entity_id)
        return _incident_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[Incident]:
        result = await self._session.execute(
            select(IncidentModel)
            .order_by(IncidentModel.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_incident_to_entity(model) for model in result.scalars()]

    async def find_open_matching(self, signature: str, *, since: datetime) -> Incident | None:
        result = await self._session.execute(
            select(IncidentModel)
            .where(
                IncidentModel.correlation_signature == signature,
                IncidentModel.status == IncidentStatus.OPEN.value,
                IncidentModel.last_seen_at >= since,
            )
            .order_by(IncidentModel.last_seen_at.desc())
        )
        model = result.scalars().first()
        return _incident_to_entity(model) if model is not None else None

    async def list_open(self) -> builtins.list[Incident]:
        result = await self._session.execute(
            select(IncidentModel).where(IncidentModel.status == IncidentStatus.OPEN.value)
        )
        return [_incident_to_entity(model) for model in result.scalars()]


def _link_to_entity(model: IncidentAccountLinkModel) -> IncidentAccountLink:
    return IncidentAccountLink(
        id=model.id,
        incident_id=model.incident_id,
        account_id=model.account_id,
        created_at=ensure_utc(model.created_at),
        updated_at=ensure_utc(model.updated_at),
    )


def _link_to_model(entity: IncidentAccountLink) -> IncidentAccountLinkModel:
    return IncidentAccountLinkModel(
        id=entity.id,
        incident_id=entity.incident_id,
        account_id=entity.account_id,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyIncidentAccountLinkRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: IncidentAccountLink) -> None:
        self._session.add(_link_to_model(entity))
        await self._session.flush()

    async def save(self, entity: IncidentAccountLink) -> None:
        await self._session.merge(_link_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> IncidentAccountLink | None:
        model = await self._session.get(IncidentAccountLinkModel, entity_id)
        return _link_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[IncidentAccountLink]:
        result = await self._session.execute(
            select(IncidentAccountLinkModel).limit(limit).offset(offset)
        )
        return [_link_to_entity(model) for model in result.scalars()]

    async def get_by_incident_and_account(
        self, incident_id: UUID, account_id: UUID
    ) -> IncidentAccountLink | None:
        result = await self._session.execute(
            select(IncidentAccountLinkModel).where(
                IncidentAccountLinkModel.incident_id == incident_id,
                IncidentAccountLinkModel.account_id == account_id,
            )
        )
        model = result.scalar_one_or_none()
        return _link_to_entity(model) if model is not None else None

    async def list_by_incident(self, incident_id: UUID) -> builtins.list[IncidentAccountLink]:
        result = await self._session.execute(
            select(IncidentAccountLinkModel).where(
                IncidentAccountLinkModel.incident_id == incident_id
            )
        )
        return [_link_to_entity(model) for model in result.scalars()]


def _timeline_entry_to_entity(model: ThreatTimelineEntryModel) -> ThreatTimelineEntry:
    return ThreatTimelineEntry(
        id=model.id,
        incident_id=model.incident_id,
        stage=model.stage,
        description=model.description,
        occurred_at=ensure_utc(model.occurred_at),
        source_event_id=model.source_event_id,
        created_at=ensure_utc(model.created_at),
        updated_at=ensure_utc(model.updated_at),
    )


def _timeline_entry_to_model(entity: ThreatTimelineEntry) -> ThreatTimelineEntryModel:
    return ThreatTimelineEntryModel(
        id=entity.id,
        incident_id=entity.incident_id,
        stage=entity.stage,
        description=entity.description,
        occurred_at=entity.occurred_at,
        source_event_id=entity.source_event_id,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


class SqlAlchemyThreatTimelineEntryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, entity: ThreatTimelineEntry) -> None:
        self._session.add(_timeline_entry_to_model(entity))
        await self._session.flush()

    async def save(self, entity: ThreatTimelineEntry) -> None:
        await self._session.merge(_timeline_entry_to_model(entity))
        await self._session.flush()

    async def get(self, entity_id: UUID) -> ThreatTimelineEntry | None:
        model = await self._session.get(ThreatTimelineEntryModel, entity_id)
        return _timeline_entry_to_entity(model) if model is not None else None

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[ThreatTimelineEntry]:
        result = await self._session.execute(
            select(ThreatTimelineEntryModel)
            .order_by(ThreatTimelineEntryModel.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_timeline_entry_to_entity(model) for model in result.scalars()]

    async def list_by_incident(self, incident_id: UUID) -> builtins.list[ThreatTimelineEntry]:
        result = await self._session.execute(
            select(ThreatTimelineEntryModel)
            .where(ThreatTimelineEntryModel.incident_id == incident_id)
            .order_by(ThreatTimelineEntryModel.occurred_at.asc())
        )
        return [_timeline_entry_to_entity(model) for model in result.scalars()]
