from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from sentinel.api.dependencies import AppSettings, DbSession, get_database
from sentinel.infrastructure.persistence.repositories.observability import (
    SqlAlchemyJobHeartbeatRepository,
)
from sentinel.infrastructure.scheduler.job_registry import ALL_JOBS, DETECTION_SCAN_JOB_IDS
from sentinel.web.dependencies import RequireAdminSession, RequireCsrfToken, templates

router = APIRouter(prefix="/scans", tags=["dashboard-scans"])

_RUN_FN_BY_JOB_ID = {job_id: run_fn for job_id, run_fn, _ in ALL_JOBS}


@router.get("")
async def list_scans(
    request: Request,
    session: DbSession,
    admin_user: RequireAdminSession,
) -> Response:
    heartbeats = await SqlAlchemyJobHeartbeatRepository(session).list(limit=100)
    heartbeat_by_job_id = {heartbeat.job_id: heartbeat for heartbeat in heartbeats}
    jobs = [
        {
            "job_id": job_id,
            "heartbeat": heartbeat_by_job_id.get(job_id),
            "triggerable": job_id in DETECTION_SCAN_JOB_IDS,
        }
        for job_id, _run_fn, _interval_fn in ALL_JOBS
    ]

    return templates.TemplateResponse(
        request,
        "scans.html",
        {
            "admin_user": admin_user,
            "jobs": jobs,
            "csrf_token": request.state.admin_session.csrf_token,
        },
    )


@router.post("/run/{job_id}")
async def run_single_scan_now(
    request: Request,
    job_id: str,
    settings: AppSettings,
    admin_user: RequireAdminSession,
    _csrf: RequireCsrfToken,
    background_tasks: BackgroundTasks,
) -> RedirectResponse:
    """Triggers exactly one detection job immediately — the per-row "Run
    Now" action on the Scan Management page. Restricted to
    ``DETECTION_SCAN_JOB_IDS`` for the same reason ``run_scan_now`` below
    excludes correlation/auto-quarantine from the "run everything" button:
    those consume what detection jobs produce and stay on their own
    schedule rather than being manually triggerable.
    """
    del admin_user
    if job_id not in DETECTION_SCAN_JOB_IDS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown scan job")
    database = get_database(request)
    background_tasks.add_task(_RUN_FN_BY_JOB_ID[job_id], database, settings)

    return RedirectResponse(url=f"{settings.dashboard_base_path}/scans", status_code=303)


@router.post("/run")
async def run_scan_now(
    request: Request,
    settings: AppSettings,
    admin_user: RequireAdminSession,
    _csrf: RequireCsrfToken,
    background_tasks: BackgroundTasks,
) -> RedirectResponse:
    """Triggers every detection scan job immediately instead of waiting for
    its next scheduled tick, via the same functions job_registry.py's
    scheduler calls (`run_x(database, settings)`), run in the background so
    the request returns right away — the dashboard then reflects progress
    by polling `/dashboard`, where each job's heartbeat updates as it
    finishes. Correlation and auto-quarantine are deliberately not
    triggered here; they consume what these scans produce and stay on
    their own schedule."""
    del admin_user
    database = get_database(request)
    for job_id in DETECTION_SCAN_JOB_IDS:
        background_tasks.add_task(_RUN_FN_BY_JOB_ID[job_id], database, settings)

    return RedirectResponse(url=settings.dashboard_base_path, status_code=303)
