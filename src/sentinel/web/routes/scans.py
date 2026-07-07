from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import RedirectResponse

from sentinel.api.dependencies import AppSettings, get_database
from sentinel.infrastructure.scheduler.job_registry import ALL_JOBS, DETECTION_SCAN_JOB_IDS
from sentinel.web.dependencies import RequireAdminSession, RequireCsrfToken

router = APIRouter(prefix="/scans", tags=["dashboard-scans"])

_RUN_FN_BY_JOB_ID = {job_id: run_fn for job_id, run_fn, _ in ALL_JOBS}


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

    return RedirectResponse(url="/dashboard", status_code=303)
