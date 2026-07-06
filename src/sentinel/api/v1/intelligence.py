from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status

from sentinel.api.dependencies import (
    GetIncident,
    ListIncidentEvidence,
    ListIncidents,
    ListIncidentTimeline,
    RequireApiKey,
)
from sentinel.api.pagination import decode_cursor, encode_cursor
from sentinel.api.schemas.common import Envelope, PaginatedEnvelope, PaginationInfo, ResponseMeta
from sentinel.api.schemas.intelligence import (
    IncidentResponse,
    SecurityEventResponse,
    ThreatTimelineEntryResponse,
)
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=PaginatedEnvelope[IncidentResponse])
async def list_incidents(
    request: Request,
    _: RequireApiKey,
    query: ListIncidents,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedEnvelope[IncidentResponse]:
    offset = decode_cursor(cursor)
    incidents = await query.execute(limit=limit + 1, offset=offset)

    has_next = len(incidents) > limit
    page = incidents[:limit]

    return PaginatedEnvelope(
        data=[IncidentResponse.from_entity(incident) for incident in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get("/{incident_id}", response_model=Envelope[IncidentResponse])
async def get_incident(
    request: Request,
    _: RequireApiKey,
    incident_id: UUID,
    query: GetIncident,
) -> Envelope[IncidentResponse]:
    try:
        incident = await query.execute(incident_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return Envelope(
        data=IncidentResponse.from_entity(incident),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get(
    "/{incident_id}/timeline",
    response_model=Envelope[list[ThreatTimelineEntryResponse]],
)
async def list_incident_timeline(
    request: Request,
    _: RequireApiKey,
    incident_id: UUID,
    query: ListIncidentTimeline,
) -> Envelope[list[ThreatTimelineEntryResponse]]:
    entries = await query.execute(incident_id)
    return Envelope(
        data=[ThreatTimelineEntryResponse.from_entity(entry) for entry in entries],
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get(
    "/{incident_id}/evidence",
    response_model=Envelope[list[SecurityEventResponse]],
)
async def list_incident_evidence(
    request: Request,
    _: RequireApiKey,
    incident_id: UUID,
    query: ListIncidentEvidence,
) -> Envelope[list[SecurityEventResponse]]:
    events = await query.execute(incident_id)
    return Envelope(
        data=[SecurityEventResponse.from_entity(event) for event in events],
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )
