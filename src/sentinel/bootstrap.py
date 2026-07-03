from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from sentinel.api.middleware import RequestContextMiddleware
from sentinel.api.v1.router import api_router
from sentinel.config import Settings, get_settings
from sentinel.infrastructure.persistence.database import Database


def configure_logging(settings: Settings) -> None:
    """All logs, from every layer, are structured JSON on stdout. This is a
    container-native deployment — there is no log file to tail on the host —
    so the only contract that matters is that stdout is valid JSON lines a
    downstream collector (Phase 5's log pipeline, or an external one) can
    parse without a regex.
    """
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=settings.log_level)

    # aiosqlite logs every single DB-API call at DEBUG via the stdlib logger,
    # bypassing structlog's JSON renderer entirely — at DEBUG level that
    # drowns out actual application logs with unstructured noise. SQLAlchemy
    # query logging is controlled separately via Settings.database_echo.
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)
    logger = structlog.get_logger()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        database = Database(settings)
        app.state.database = database
        app.state.settings = settings
        logger.info("sentinel_core_startup", environment=settings.environment)
        try:
            yield
        finally:
            await database.dispose()
            logger.info("sentinel_core_shutdown")

    app = FastAPI(
        title="Sentinel Core",
        description="Kloud101 AI Sentinel — Core Monitoring Engine API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(RequestContextMiddleware)
    app.include_router(api_router)
    return app


app = create_app()
