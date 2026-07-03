from __future__ import annotations

from fastapi import APIRouter, Query, Request

from sentinel.api.dependencies import ListCpanelAccounts, RequireApiKey
from sentinel.api.pagination import decode_cursor, encode_cursor
from sentinel.api.schemas.common import PaginatedEnvelope, PaginationInfo, ResponseMeta
from sentinel.api.schemas.discovery import CpanelAccountResponse
from sentinel.domain.shared.entity import utcnow

router = APIRouter(prefix="/accounts", tags=["discovery"])


@router.get("", response_model=PaginatedEnvelope[CpanelAccountResponse])
async def list_accounts(
    request: Request,
    _: RequireApiKey,
    query: ListCpanelAccounts,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedEnvelope[CpanelAccountResponse]:
    offset = decode_cursor(cursor)
    accounts = await query.execute(limit=limit + 1, offset=offset)

    has_next = len(accounts) > limit
    page = accounts[:limit]

    return PaginatedEnvelope(
        data=[CpanelAccountResponse.from_entity(account) for account in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )
