from __future__ import annotations

from collections.abc import Awaitable, Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = structlog.get_logger()


class SchedulerAdapter:
    """Thin wrapper around APScheduler's ``AsyncIOScheduler``.

    Job registration lives in ``job_registry.py`` and stays empty until each
    monitoring use case exists. Phase 0's only job is to prove the scheduler
    boots, runs its event loop alongside the rest of the worker process, and
    shuts down cleanly — the two-container (API + worker) topology decided in
    the architecture doc.
    """

    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()

    def add_interval_job(
        self, func: Callable[[], Awaitable[None]], *, minutes: int, job_id: str
    ) -> None:
        self._scheduler.add_job(
            func,
            trigger="interval",
            minutes=minutes,
            id=job_id,
            replace_existing=True,
            misfire_grace_time=None,
            coalesce=True,
            max_instances=1,
        )

    def start(self) -> None:
        self._scheduler.start()
        logger.info("scheduler_started", job_count=len(self._scheduler.get_jobs()))

    def shutdown(self) -> None:
        self._scheduler.shutdown(wait=True)
        logger.info("scheduler_stopped")
