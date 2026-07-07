from __future__ import annotations

from fastapi import APIRouter, Request, Response

from sentinel.api.dependencies import DbSession
from sentinel.application.observability.queries import (
    GetDashboardSummaryQuery,
    GetSystemStatusQuery,
)
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
)
from sentinel.infrastructure.persistence.repositories.events import SqlAlchemyEventRepository
from sentinel.infrastructure.persistence.repositories.forensics import (
    SqlAlchemyTempFileObservationRepository,
)
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyIntegrityFindingRepository,
)
from sentinel.infrastructure.persistence.repositories.observability import (
    SqlAlchemyJobHeartbeatRepository,
)
from sentinel.web.dependencies import RequireAdminSession, templates

router = APIRouter(tags=["dashboard"])


@router.get("/")
async def dashboard_home(
    request: Request,
    session: DbSession,
    admin_user: RequireAdminSession,
) -> Response:
    finding_repository = SqlAlchemyIntegrityFindingRepository(session)
    event_repository = SqlAlchemyEventRepository(session)
    query = GetDashboardSummaryQuery(
        system_status_query=GetSystemStatusQuery(
            heartbeat_repository=SqlAlchemyJobHeartbeatRepository(session),
            event_repository=event_repository,
            finding_repository=finding_repository,
            observation_repository=SqlAlchemyTempFileObservationRepository(session),
        ),
        account_repository=SqlAlchemyCpanelAccountRepository(session),
        event_repository=event_repository,
        finding_repository=finding_repository,
    )
    summary = await query.execute()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "admin_user": admin_user,
            "summary": summary,
            "csrf_token": request.state.admin_session.csrf_token,
        },
    )
