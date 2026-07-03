from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status

from sentinel.api.dependencies import (
    AcknowledgeIntegrityFinding,
    ListFileBaselines,
    ListIntegrityFindings,
    RequireApiKey,
)
from sentinel.api.pagination import decode_cursor, encode_cursor
from sentinel.api.schemas.common import Envelope, PaginatedEnvelope, PaginationInfo, ResponseMeta
from sentinel.api.schemas.integrity import FileBaselineResponse, IntegrityFindingResponse
from sentinel.domain.shared.entity import utcnow
from sentinel.domain.shared.exceptions import EntityNotFoundError

router = APIRouter(prefix="/integrity", tags=["integrity"])


@router.get("/baselines", response_model=PaginatedEnvelope[FileBaselineResponse])
async def list_baselines(
    request: Request,
    _: RequireApiKey,
    query: ListFileBaselines,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedEnvelope[FileBaselineResponse]:
    offset = decode_cursor(cursor)
    baselines = await query.execute(limit=limit + 1, offset=offset)

    has_next = len(baselines) > limit
    page = baselines[:limit]

    return PaginatedEnvelope(
        data=[FileBaselineResponse.from_entity(baseline) for baseline in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get("/findings", response_model=PaginatedEnvelope[IntegrityFindingResponse])
async def list_findings(
    request: Request,
    _: RequireApiKey,
    query: ListIntegrityFindings,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    unacknowledged_only: bool = False,
) -> PaginatedEnvelope[IntegrityFindingResponse]:
    offset = decode_cursor(cursor)
    findings = await query.execute(
        limit=limit + 1, offset=offset, unacknowledged_only=unacknowledged_only
    )

    has_next = len(findings) > limit
    page = findings[:limit]

    return PaginatedEnvelope(
        data=[IntegrityFindingResponse.from_entity(finding) for finding in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.post(
    "/findings/{finding_id}/acknowledge",
    response_model=Envelope[IntegrityFindingResponse],
)
async def acknowledge_finding(
    request: Request,
    _: RequireApiKey,
    finding_id: UUID,
    use_case: AcknowledgeIntegrityFinding,
) -> Envelope[IntegrityFindingResponse]:
    try:
        finding = await use_case.execute(finding_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return Envelope(
        data=IntegrityFindingResponse.from_entity(finding),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )
