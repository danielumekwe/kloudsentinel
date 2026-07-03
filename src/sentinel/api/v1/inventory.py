from __future__ import annotations

from fastapi import APIRouter, Query, Request

from sentinel.api.dependencies import ListInstalledPlugins, ListInstalledThemes, RequireApiKey
from sentinel.api.pagination import decode_cursor, encode_cursor
from sentinel.api.schemas.common import PaginatedEnvelope, PaginationInfo, ResponseMeta
from sentinel.api.schemas.inventory import InstalledPluginResponse, InstalledThemeResponse
from sentinel.domain.shared.entity import utcnow

router = APIRouter(prefix="/inventory", tags=["inventory"])


@router.get("/plugins", response_model=PaginatedEnvelope[InstalledPluginResponse])
async def list_plugins(
    request: Request,
    _: RequireApiKey,
    query: ListInstalledPlugins,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedEnvelope[InstalledPluginResponse]:
    offset = decode_cursor(cursor)
    plugins = await query.execute(limit=limit + 1, offset=offset)

    has_next = len(plugins) > limit
    page = plugins[:limit]

    return PaginatedEnvelope(
        data=[InstalledPluginResponse.from_entity(plugin) for plugin in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )


@router.get("/themes", response_model=PaginatedEnvelope[InstalledThemeResponse])
async def list_themes(
    request: Request,
    _: RequireApiKey,
    query: ListInstalledThemes,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedEnvelope[InstalledThemeResponse]:
    offset = decode_cursor(cursor)
    themes = await query.execute(limit=limit + 1, offset=offset)

    has_next = len(themes) > limit
    page = themes[:limit]

    return PaginatedEnvelope(
        data=[InstalledThemeResponse.from_entity(theme) for theme in page],
        pagination=PaginationInfo(
            cursor_next=encode_cursor(offset + limit) if has_next else None,
            cursor_prev=encode_cursor(max(0, offset - limit)) if offset > 0 else None,
            has_next=has_next,
            has_prev=offset > 0,
            limit=limit,
        ),
        meta=ResponseMeta(request_id=request.state.request_id, timestamp=utcnow()),
    )
