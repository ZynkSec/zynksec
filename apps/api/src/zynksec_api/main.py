"""Zynksec API entry point.

Week 2 — includes the health + scans routers, wires the DB session
dependency, registers the canonical error-shape handler, and keeps
the Week-1 request-id middleware.
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

_REQUEST_ID_HEADER = "X-Request-ID"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request id to every log line for the request's scope."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        inbound = request.headers.get(_REQUEST_ID_HEADER)
        request_id = inbound or str(uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            path=request.url.path,
            method=request.method,
        )
        response = await call_next(request)
        response.headers[_REQUEST_ID_HEADER] = request_id
        return response


async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.zynksec_log_level)
    structlog.get_logger().info(
        "api.startup",
        version=__version__,
        env=settings.zynksec_env,
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
    app.add_middleware(RequestIdMiddleware)
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
