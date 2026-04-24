"""Health router — ``GET /api/v1/health`` liveness probe.

Extracted from ``main.py`` in Week 2 so routers stay in one place.
The compact literal body (no spaces) is preserved verbatim to stay
byte-compatible with the Phase-0 DoD from Week 1.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

router = APIRouter(prefix="/api/v1", tags=["health"])

_HEALTH_BODY = b'{"status":"ok","service":"zynksec-api"}'


@router.get("/health")
async def health() -> Response:
    return Response(content=_HEALTH_BODY, media_type="application/json")
