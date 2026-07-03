from __future__ import annotations

from fastapi import APIRouter, Query, Request

from sentinel.api.dependencies import ListConfigurationItems, RequireApiKey
from sentinel.api.pagination import decode_cursor, encode_cursor
from sentinel.api.schemas.common import PaginatedEnvelope, PaginationInfo, ResponseMeta
from sentinel.api.schemas.monitoring import ConfigurationItemResponse
from sentinel.domain.shared.entity import utcnow

router = APIRouter(prefix="/configuration", tags=["configuration"])


@router.get("/items", response_model=PaginatedEnvelope[ConfigurationItemResponse])
async def list_configuration_items(
    request: Request,
    _: RequireApiKey,
    query: ListConfigurationItems,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedEnvelope[ConfigurationItemResponse]:
    offset = decode_cursor(cursor)
    items = await query.execute(limit=limit + 1, offset=offset)

    has_next = len(items) > limit
    page = items[:limit]

    return PaginatedEnvelope(
        data=[ConfigurationItemResponse.from_entity(item) for item in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )
