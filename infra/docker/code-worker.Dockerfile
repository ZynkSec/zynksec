# Pinned by digest. Bump via Dependabot or manual checksum re-verification.
#
# Multi-stage build for the Zynksec code-worker (Phase 3 Sprint 1+).
#
# Sibling of ``infra/docker/worker.Dockerfile`` — same Python venv +
# Celery entry-point — but additionally installs:
#   * ``git`` (the cloner shells out to it)
#   * ``gitleaks`` (Phase 3 Sprint 1's repo scanner)
#
# The split is deliberate.  ZAP workers don't need git or gitleaks;
# baking them into the ZAP worker image would bloat it and tie the
# two scanner families' release cadences together.  The compose
# service ``code-worker`` is built from this file and joins
# zynksec-core + zynksec-scan only — code workers never reach the
# zynksec-targets network.
#
# Phase 3 cleanup item #2: every external artefact (base images,
# gitleaks tarball) is pinned by content-addressable hash.  Tag-only
# pins let upstream silently rebuild the image with a different SHA;
# pinning by ``@sha256:<digest>`` (images) or
# ``sha256sum -c`` (binaries) means reproducible builds and a
# tampered upstream fails the build loudly.  Bumping a pin is
# Dependabot's job — or a one-line edit + a manual checksum
# re-verification against the upstream release page.

# Base images pinned by digest.  Tag stays in the ARG default for
# operator legibility ("which version did we pin?") but ``@sha256:``
# is the load-bearing identifier.
ARG PYTHON_IMAGE=python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347

# ---------- Gitleaks pin ----------
# 8.18.4 was the latest stable when this Dockerfile landed.  Pinning
# by patch keeps reproducibility tight; the SHA-256s below are read
# verbatim from the upstream ``_checksums.txt`` shipped with the
# release.  Bumping the pin requires a one-line edit (version) plus
# a manual fetch of the new checksums; a CI rerun against the
# gitfixture (with its known plants) verifies the binary still
# detects the canonical AKIA / ghp_ / Slack-webhook patterns.
ARG GITLEAKS_VERSION=8.18.4
ARG GITLEAKS_SHA256_AMD64=ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d
ARG GITLEAKS_SHA256_ARM64=bf5f7f466ebfade1296c8bd32cf7d3f592c2aa78836aa9980ffbe2cadca7a861

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
# workspace member it imports (transitively).  Same set as the ZAP
# worker — gitleaks is delivered as a CLI binary, not a Python dep.
COPY pyproject.toml uv.lock ./
COPY apps/worker ./apps/worker
COPY packages/db ./packages/db
COPY packages/shared-schema ./packages/shared-schema
COPY packages/scanners ./packages/scanners

RUN uv sync --package zynksec-worker --frozen --no-dev

# ---------- Gitleaks fetcher ----------
# Separate stage so the gitleaks tarball + curl + the verification
# step are all isolated from the runtime image; only the binary
# survives the COPY into runtime.  ``curl -fsSL`` per CLAUDE.md §14
# (no missing -f → no silent HTTP-error → "not in gzip format"
# rabbit-hole the next time gitleaks moves their release naming).
FROM ${PYTHON_IMAGE} AS gitleaks-stage
ARG GITLEAKS_VERSION
ARG GITLEAKS_SHA256_AMD64
ARG GITLEAKS_SHA256_ARM64
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && ARCH="$(dpkg --print-architecture)" \
 && case "$ARCH" in \
      amd64) GITLEAKS_ARCH=linux_x64; EXPECTED_SHA="${GITLEAKS_SHA256_AMD64}" ;; \
      arm64) GITLEAKS_ARCH=linux_arm64; EXPECTED_SHA="${GITLEAKS_SHA256_ARM64}" ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSLo /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" \
 && echo "${EXPECTED_SHA}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks \
 && install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks \
 && /usr/local/bin/gitleaks version

# ---------- Runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

ARG APP_UID=1001
ARG APP_GID=1001
RUN groupadd --system --gid ${APP_GID} zynksec \
 && useradd  --system --gid zynksec --uid ${APP_UID} --no-log-init \
             --home /app --shell /usr/sbin/nologin zynksec

# git is required by the cloner.  ca-certificates is required for
# https clones to verify their TLS chain (CLAUDE.md §6 — TLS
# verification is never disabled).  --no-install-recommends keeps the
# image lean (~140 MB total instead of ~280 MB with recommended deps).
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gitleaks-stage /usr/local/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app
COPY --from=builder --chown=zynksec:zynksec /app /app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WORKER_FAMILY=code

USER zynksec

# Subscribe ONLY to ``code_q`` — code workers never service ZAP
# tasks.  The compose ``command:`` override is allowed to add
# ``--concurrency`` if an operator wants to fan out further; default
# (cpu_count) is fine for a single-tenant dev stack.
CMD ["celery", "-A", "zynksec_worker.celery_app", "worker", "--loglevel=INFO", "--queues=code_q"]
