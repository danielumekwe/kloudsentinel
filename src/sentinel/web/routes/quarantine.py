from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from sentinel.api.dependencies import AppSettings, DbSession, require_mutations_allowed
from sentinel.application.integrity.queries import ListQuarantinedFindingsQuery
from sentinel.application.integrity.use_cases import DeleteFindingUseCase, RestoreFindingUseCase
from sentinel.domain.shared.exceptions import EntityNotFoundError, InvariantViolationError
from sentinel.infrastructure.filesystem.file_remediator import FilesystemFileRemediator
from sentinel.infrastructure.persistence.repositories.discovery import (
    SqlAlchemyCpanelAccountRepository,
)
from sentinel.infrastructure.persistence.repositories.integrity import (
    SqlAlchemyFileBaselineRepository,
    SqlAlchemyIntegrityFindingRepository,
    SqlAlchemyRemediationActionRepository,
)
from sentinel.web.dependencies import RequireAdminSession, RequireCsrfToken, templates

router = APIRouter(prefix="/quarantine", tags=["dashboard-quarantine"])


@router.get("")
async def list_quarantine(
    request: Request,
    session: DbSession,
    admin_user: RequireAdminSession,
) -> Response:
    query = ListQuarantinedFindingsQuery(SqlAlchemyIntegrityFindingRepository(session))
    findings = await query.execute()

    return templates.TemplateResponse(
        request,
        "quarantine.html",
        {
            "admin_user": admin_user,
            "findings": findings,
            "csrf_token": request.state.admin_session.csrf_token,
        },
    )


@router.post("/{finding_id}/restore")
async def restore_quarantined_file(
    finding_id: UUID,
    session: DbSession,
    settings: AppSettings,
    admin_user: RequireAdminSession,
    _csrf: RequireCsrfToken,
) -> RedirectResponse:
    del admin_user
    require_mutations_allowed(settings)
    use_case = RestoreFindingUseCase(
        finding_repository=SqlAlchemyIntegrityFindingRepository(session),
        account_repository=SqlAlchemyCpanelAccountRepository(session),
        baseline_repository=SqlAlchemyFileBaselineRepository(session),
        action_repository=SqlAlchemyRemediationActionRepository(session),
        remediator=FilesystemFileRemediator(
            quarantine_root_directory=settings.quarantine_root_directory
        ),
    )
    try:
        await use_case.execute(finding_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvariantViolationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return RedirectResponse(url=f"{settings.dashboard_base_path}/quarantine", status_code=303)


@router.post("/{finding_id}/delete")
async def delete_quarantined_file(
    finding_id: UUID,
    session: DbSession,
    settings: AppSettings,
    admin_user: RequireAdminSession,
    _csrf: RequireCsrfToken,
) -> RedirectResponse:
    """Permanently purges an already-quarantined file — the one
    irreversible action the dashboard exposes. Everything up to this point
    (quarantine, restore) is reversible; this is not, which is why it's a
    distinct confirmation step in the UI rather than a single click."""
    del admin_user
    require_mutations_allowed(settings)
    use_case = DeleteFindingUseCase(
        finding_repository=SqlAlchemyIntegrityFindingRepository(session),
        action_repository=SqlAlchemyRemediationActionRepository(session),
        remediator=FilesystemFileRemediator(
            quarantine_root_directory=settings.quarantine_root_directory
        ),
    )
    try:
        await use_case.execute(finding_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvariantViolationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return RedirectResponse(url=f"{settings.dashboard_base_path}/quarantine", status_code=303)
