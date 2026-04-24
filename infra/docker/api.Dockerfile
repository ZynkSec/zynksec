# Multi-stage build for the Zynksec API.
#   builder  — uv installs the workspace + pinned deps into /app/.venv
#   runtime  — python:3.12.7-slim, non-root, carries only the virtualenv
#              and the app source (no build tools).

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

# Workspace root + lockfile, then the three workspace members that the
# API depends on (transitively).  Copying this way keeps the context
# narrow without losing the workspace graph.
COPY pyproject.toml uv.lock ./
COPY apps/api ./apps/api
COPY packages/shared-schema ./packages/shared-schema
COPY packages/scanners ./packages/scanners

RUN uv sync --package zynksec-api --frozen --no-dev

# ---------- Runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

# Non-root user; matches UID/GID to keep volume perms sane.
ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --system --gid ${APP_GID} zynksec \
 && useradd  --system --gid zynksec --uid ${APP_UID} --no-log-init \
             --home /app --shell /usr/sbin/nologin zynksec

WORKDIR /app
COPY --from=builder --chown=zynksec:zynksec /app /app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ZYNKSEC_API_HOST=0.0.0.0 \
    ZYNKSEC_API_PORT=8000

USER zynksec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=2).status==200 else 1)"

# Entry point comes from apps/api/pyproject.toml [project.scripts]
# (zynksec_api.main:run).  It reads host/port from pydantic-settings.
CMD ["zynksec-api"]
