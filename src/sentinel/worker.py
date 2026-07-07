from __future__ import annotations

import asyncio
import signal

import structlog

from sentinel.bootstrap import configure_logging
from sentinel.config import get_settings
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.scheduler.apscheduler_adapter import SchedulerAdapter
from sentinel.infrastructure.scheduler.job_registry import register_jobs
from sentinel.infrastructure.validation import has_critical_failures, run_all_checks

logger = structlog.get_logger()


async def main() -> None:
    settings = get_settings()
    configure_logging(settings)

    results = await run_all_checks(settings)
    for result in results:
        log_method = {"PASS": logger.info, "WARN": logger.warning, "FAIL": logger.error}[
            result.status
        ]
        log_method("startup_check", name=result.name, status=result.status, detail=result.detail)
    if has_critical_failures(results):
        logger.error("sentinel_worker_startup_aborted")
        raise RuntimeError(
            "Sentinel worker failed startup validation — see startup_check log lines above"
        )

    database = Database(settings)
    scheduler = SchedulerAdapter()
    register_jobs(scheduler, database=database, settings=settings)
    scheduler.start()

    logger.info("worker_started", environment=settings.environment)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()

    logger.info("worker_stopping")
    scheduler.shutdown()
    await database.dispose()


if __name__ == "__main__":
    asyncio.run(main())
