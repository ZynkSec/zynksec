# zynksec-api

FastAPI service for Zynksec.

## Status

Phase 0 Week 1 ships only:

- `GET /api/v1/health` — liveness probe.
- `pydantic-settings` config backed by `.env` / container env.
- `structlog` JSON logging with a per-request `X-Request-ID`
  propagated via `contextvars`.

Week 2 adds DB models, Alembic, `/api/v1/projects` and `/api/v1/scans`
routes. `/api/v1/ready` (readiness) lands with the DB layer.
