"""Zynksec API entry point.

Week 4 — rebrands the request-tracing header to ``X-Correlation-Id``
and the bound contextvar to ``correlation_id`` so a single identifier
follows a request through the API, the Celery task, the worker, and
the scanner (docs/04 observability contract).  Error-response bodies
continue to expose the value under the ``request_id`` key per
CLAUDE.md §4 — the key name is locked; the value is the same.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from zynksec_api import __version__
from zynksec_api.config import get_settings
from zynksec_api.exceptions import ZynksecError
from zynksec_api.logging_config import configure_logging
from zynksec_api.routers import health, scans

_CORRELATION_ID_HEADER = "X-Correlation-Id"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach a correlation id to every log line for the request's scope.

    Honours an inbound ``X-Correlation-Id`` header when present (so a
    caller can thread its own id through).  Otherwise generates a
    UUIDv4.  Every log line emitted during the request carries
    ``correlation_id=<uuid>`` via structlog's contextvars merge
    processor.  The same value is echoed in the response header so the
    caller can correlate client-side.

    Emits a single ``http.request`` structlog line after the handler
    returns so each request produces at least one structured log row
    carrying the correlation_id — even when the handler body itself
    logs nothing (uvicorn's access logs bypass structlog).
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        inbound = request.headers.get(_CORRELATION_ID_HEADER)
        correlation_id = inbound or str(uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            path=request.url.path,
            method=request.method,
        )
        response = await call_next(request)
        response.headers[_CORRELATION_ID_HEADER] = correlation_id
        structlog.get_logger().info(
            "http.request",
            status_code=response.status_code,
        )
        return response


async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.zynksec_log_level, settings.zynksec_log_format)
    structlog.get_logger().info(
        "api.startup",
        version=__version__,
        env=settings.zynksec_env,
        log_format=settings.zynksec_log_format,
    )
    yield
    structlog.get_logger().info("api.shutdown")


def _zynksec_error_handler(request: Request, exc: ZynksecError) -> JSONResponse:
    """Flatten Starlette's ``{"detail": ...}`` wrapper into the
    canonical ``{code, message, request_id, [details]}`` shape
    (CLAUDE.md §4).
    """
    del request  # unused; interface demanded by FastAPI
    return JSONResponse(exc.detail, status_code=exc.status_code)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Zynksec API",
        version=__version__,
        lifespan=_lifespan,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.add_exception_handler(ZynksecError, _zynksec_error_handler)  # type: ignore[arg-type]

    app.include_router(health.router)
    app.include_router(scans.router)
    return app


app = create_app()


def run() -> None:
    """CLI entry point for ``uv run zynksec-api``."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "zynksec_api.main:app",
        host=settings.zynksec_api_host,
        port=settings.zynksec_api_port,
        reload=settings.zynksec_env == "dev",
    )
