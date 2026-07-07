from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from sentinel.api.dependencies import DbSession
from sentinel.application.integrity.queries import (
    AcknowledgeIntegrityFindingUseCase,
    ListIntegrityFindingsQuery,
)
from sentinel.domain.shared.exceptions import EntityNotFoundError
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyIntegrityFindingRepository,
)
from sentinel.web.dependencies import RequireAdminSession, RequireCsrfToken, templates

router = APIRouter(prefix="/threats", tags=["dashboard-threats"])


@router.get("")
async def list_threats(
    request: Request,
    session: DbSession,
    admin_user: RequireAdminSession,
    unacknowledged_only: bool = False,
) -> Response:
    query = ListIntegrityFindingsQuery(SqlAlchemyIntegrityFindingRepository(session))
    findings = await query.execute(limit=100, offset=0, unacknowledged_only=unacknowledged_only)

    return templates.TemplateResponse(
        request,
        "threats.html",
        {
            "admin_user": admin_user,
            "findings": findings,
            "unacknowledged_only": unacknowledged_only,
            "csrf_token": request.state.admin_session.csrf_token,
        },
    )


@router.post("/{finding_id}/acknowledge")
async def acknowledge_threat(
    finding_id: UUID,
    session: DbSession,
    admin_user: RequireAdminSession,
    _csrf: RequireCsrfToken,
) -> RedirectResponse:
    del admin_user
    use_case = AcknowledgeIntegrityFindingUseCase(SqlAlchemyIntegrityFindingRepository(session))
    try:
        await use_case.execute(finding_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return RedirectResponse(url="/dashboard/threats", status_code=303)
