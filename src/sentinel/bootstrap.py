from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from sentinel.api.middleware import MaxBodySizeMiddleware, RequestContextMiddleware
from sentinel.api.v1.router import api_router
from sentinel.config import Settings, get_settings
from sentinel.infrastructure.persistence.database import Database
from sentinel.infrastructure.validation import has_critical_failures, run_all_checks
from sentinel.web.dependencies import RedirectToLogin
from sentinel.web.router import web_router


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
        results = await run_all_checks(settings)
        for result in results:
            log_method = {"PASS": logger.info, "WARN": logger.warning, "FAIL": logger.error}[
                result.status
            ]
            log_method(
                "startup_check", name=result.name, status=result.status, detail=result.detail
            )
        if has_critical_failures(results):
            logger.error("sentinel_core_startup_aborted")
            raise RuntimeError(
                "Sentinel failed startup validation — see startup_check log lines above"
            )

        database = Database(settings)
        app.state.database = database
        app.state.settings = settings
        logger.info("sentinel_core_startup", environment=settings.environment, mode=settings.mode)
        try:
            yield
        finally:
            await database.dispose()
            logger.info("sentinel_core_shutdown")

    app = FastAPI(
        title="Sentinel Core",
        description="Kloud101 AI Sentinel — Core Monitoring Engine API",
        version="1.0.0",
        lifespan=lifespan,
    )
    # Registration order matters: Starlette wraps middleware outside-in in
    # reverse of add_middleware() call order, so MaxBodySizeMiddleware
    # (added first, innermost) runs its check before any route/dependency
    # code touches the body, while RequestContextMiddleware (added last,
    # outermost) still wraps it — a rejected oversized request gets an
    # access-log line too, not silently dropped before request_id/logging
    # are set up.
    app.add_middleware(MaxBodySizeMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.include_router(api_router)
    app.include_router(web_router)

    static_dir = Path(__file__).parent / "web" / "static"
    app.mount("/dashboard/static", StaticFiles(directory=str(static_dir)), name="dashboard-static")

    @app.exception_handler(RedirectToLogin)
    async def _redirect_to_login(request: Request, exc: RedirectToLogin) -> RedirectResponse:
        del request, exc
        return RedirectResponse(url="/dashboard/login", status_code=303)

    return app


app = create_app()
