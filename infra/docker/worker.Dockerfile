# Multi-stage build for the Zynksec Celery worker.
#   builder — uv installs apps/worker + its workspace deps into /app/.venv
#   runtime — python:3.12.7-slim, non-root, carries the virtualenv only.

ARG PYTHON_IMAGE=python:3.12.7-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11

# ---------- Builder ----------
FROM ${UV_IMAGE} AS uv-stage

FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv-stage /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1

WORKDIR /app

# Workspace root + lockfile, then the worker package and every
# workspace member it imports (transitively).
COPY pyproject.toml uv.lock ./
COPY apps/worker ./apps/worker
COPY packages/db ./packages/db
COPY packages/shared-schema ./packages/shared-schema
COPY packages/scanners ./packages/scanners

RUN uv sync --package zynksec-worker --frozen --no-dev

# ---------- Runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --system --gid ${APP_GID} zynksec \
 && useradd  --system --gid zynksec --uid ${APP_UID} --no-log-init \
             --home /app --shell /usr/sbin/nologin zynksec

WORKDIR /app
COPY --from=builder --chown=zynksec:zynksec /app /app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER zynksec

# Worker runs the `scans` queue only for Phase 0.  Week 3 will fan out
# to additional queues (scanners.recon, scanners.web) by changing this
# CMD or by setting worker-specific flags via compose.
CMD ["celery", "-A", "zynksec_worker.celery_app", "worker", "--loglevel=INFO", "--queues=scans"]
