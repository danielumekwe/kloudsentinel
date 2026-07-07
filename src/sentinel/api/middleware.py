from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

import structlog
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

logger = structlog.get_logger()

#: Every current request body (dashboard login/CSRF forms, JSON API
#: bodies) is at most a few hundred bytes — this is a generous ceiling
#: meant only to stop a client from forcing the server to buffer an
#: arbitrarily large body in memory. Checked against the declared
#: Content-Length header before the body is read; a client that omits
#: Content-Length or lies about it via chunked transfer-encoding isn't
#: caught here — a reverse proxy in front of Sentinel (nginx
#: `client_max_body_size`, etc.) should enforce the same limit at the
#: network edge in production.
_MAX_REQUEST_BODY_BYTES = 1_048_576


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > _MAX_REQUEST_BODY_BYTES:
                return PlainTextResponse(
                    "Request body too large",
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                )
        return await call_next(request)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request ID, binds it into structlog's context, and emits one
    structured access-log line per request. Every log emitted further down the
    call stack during this request — by a use case, a repository, anything —
    automatically carries the same ``request_id`` without it being threaded
    through every function signature.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)

        duration_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
        )
        return response
