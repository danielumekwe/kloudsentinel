from __future__ import annotations

import asyncio
import signal

import structlog

from sentinel.bootstrap import configure_logging
from sentinel.config import get_settings
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.scheduler.apscheduler_adapter import SchedulerAdapter
from sentinel.infrastructure.scheduler.job_registry import register_jobs

logger = structlog.get_logger()


async def main() -> None:
    settings = get_settings()
    configure_logging(settings)

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
