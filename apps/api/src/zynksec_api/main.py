"""Zynksec API entry point.

Phase 0 Week 1 — a single ``GET /api/v1/health`` route plus the
structured-logging + request-id middleware that every later route
relies on.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import APIRouter, FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from zynksec_api import __version__
from zynksec_api.config import get_settings
from zynksec_api.logging_config import configure_logging

_REQUEST_ID_HEADER = "X-Request-ID"
_SERVICE_NAME = "zynksec-api"
_HEALTH_BODY = b'{"status":"ok","service":"zynksec-api"}'


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


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.zynksec_log_level)
    structlog.get_logger().info(
        "api.startup",
        version=__version__,
        env=settings.zynksec_env,
    )
    yield
    structlog.get_logger().info("api.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Zynksec API",
        version=__version__,
        lifespan=lifespan,
    )
    app.add_middleware(RequestIdMiddleware)

    api_v1 = APIRouter(prefix="/api/v1")

    @api_v1.get("/health")
    async def health() -> Response:
        # Exact-byte body matches the Phase-0 DoD literal (session brief
        # §7.3 — curl -sf /api/v1/health).
        return Response(content=_HEALTH_BODY, media_type="application/json")

    app.include_router(api_v1)
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
