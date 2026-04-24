"""Health router — ``GET /api/v1/health`` liveness + ``/api/v1/ready`` readiness.

Liveness vs readiness (docs/04 §0.14 / Week-4 observability):

- ``/health`` answers "is this process up?".  No dep checks.  Always
  200.  Used by orchestrators to decide when to restart a crashed
  container — a SLOW or STALLED check here is worse than a failed
  one because it delays the restart.

- ``/ready`` answers "should this process receive traffic right now?".
  Returns 200 only if Postgres and Redis are both reachable; 503
  otherwise, with per-dep status so an operator can see which dep
  is down.  GlitchTip is deliberately NOT checked — the error
  tracker failing must never take down the API surface.  Each dep
  check has a bounded 1-second timeout so a stalled dep doesn't
  stall the probe itself.
"""

from __future__ import annotations

import asyncio
import contextlib

import redis.asyncio as redis_async
import structlog
from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text

from zynksec_api.config import get_settings
from zynksec_api.db import _engine

router = APIRouter(prefix="/api/v1", tags=["health"])

_HEALTH_BODY = b'{"status":"ok","service":"zynksec-api"}'
_READY_CHECK_TIMEOUT_S = 1.0

_log = structlog.get_logger(__name__)


@router.get("/health")
async def health() -> Response:
    """Liveness — 200 if the process is up.  Deliberately cheap."""
    return Response(content=_HEALTH_BODY, media_type="application/json")


@router.get("/ready")
async def ready() -> JSONResponse:
    """Readiness — 200 iff Postgres + Redis are reachable, 503 otherwise."""
    checks: dict[str, str] = {}
    all_ok = True

    checks["db"], db_ok = await _check_db()
    all_ok = all_ok and db_ok

    checks["redis"], redis_ok = await _check_redis()
    all_ok = all_ok and redis_ok

    body = {
        "status": "ready" if all_ok else "not_ready",
        "checks": checks,
    }
    return JSONResponse(body, status_code=200 if all_ok else 503)


async def _check_db() -> tuple[str, bool]:
    """Run ``SELECT 1`` against Postgres with a 1-second timeout."""

    def _probe() -> None:
        engine = _engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")).scalar_one()

    try:
        await asyncio.wait_for(asyncio.to_thread(_probe), timeout=_READY_CHECK_TIMEOUT_S)
    except TimeoutError:
        return ("down: timeout", False)
    except Exception as exc:  # noqa: BLE001 — readiness must never raise
        return (f"down: {type(exc).__name__}", False)
    return ("ok", True)


async def _check_redis() -> tuple[str, bool]:
    """Run ``PING`` against Redis with a 1-second socket + op timeout."""
    client = None
    try:
        client = redis_async.from_url(
            get_settings().redis_url,
            socket_connect_timeout=_READY_CHECK_TIMEOUT_S,
            socket_timeout=_READY_CHECK_TIMEOUT_S,
        )
        await asyncio.wait_for(client.ping(), timeout=_READY_CHECK_TIMEOUT_S)
    except TimeoutError:
        return ("down: timeout", False)
    except Exception as exc:  # noqa: BLE001 — readiness must never raise
        return (f"down: {type(exc).__name__}", False)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.aclose()
    return ("ok", True)
