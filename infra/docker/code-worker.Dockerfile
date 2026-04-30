# Pinned by digest. Bump via Dependabot or manual checksum re-verification.
#
# Multi-stage build for the Zynksec code-worker (Phase 3 Sprint 1+).
#
# Sibling of ``infra/docker/worker.Dockerfile`` — same Python venv +
# Celery entry-point — but additionally installs:
#   * ``git`` (the cloner shells out to it)
#   * ``gitleaks`` (Phase 3 Sprint 1's repo scanner)
#   * ``semgrep`` (Phase 3 Sprint 2's SAST scanner)
#   * ``osv-scanner`` (Phase 3 Sprint 3's dependency scanner)
#
# The split is deliberate.  ZAP workers don't need git, gitleaks,
# or semgrep; baking them into the ZAP worker image would bloat it
# and tie the scanner families' release cadences together.  The
# compose service ``code-worker`` is built from this file and joins
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

# ---------- OSV-Scanner pin ----------
# Phase 3 Sprint 3.  osv-scanner is a Go binary distributed as a
# direct executable (no tarball wrapper) on GitHub releases —
# similar to gitleaks but the asset is the bare binary, so the
# ``tar -xzf`` step is skipped.  SHA-256s below are read verbatim
# from the upstream ``osv-scanner_SHA256SUMS`` file shipped with
# the release.  Bumping the pin = one-line edit (version) + a
# manual fetch of the new checksums; CI rerun against the
# gitfixture lockfile (with its known lodash@4.17.20 vulns)
# verifies the binary still detects them.
ARG OSV_SCANNER_VERSION=2.3.5
ARG OSV_SCANNER_SHA256_AMD64=bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b
ARG OSV_SCANNER_SHA256_ARM64=fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50

# ---------- Semgrep pin ----------
# Phase 3 Sprint 2.  Semgrep ships as a Python package on PyPI
# rather than a release-tarball binary, so the integrity story is
# different from gitleaks: we rely on
#   1. The exact-version pin (``semgrep==<X>``) so PyPI's resolver
#      can't drift to a newer release silently.
#   2. ``pip install`` over HTTPS to PyPI — TLS verifies PyPI's
#      cert via the system CA bundle (``ca-certificates`` apt
#      package) so a network-MITM attacker can't substitute the
#      wheel without a valid PyPI cert.
#   3. PyPI's own server-side integrity (PEP 503 metadata + the
#      wheel SHA-256 PyPI publishes alongside each release).
#
# This is weaker than the gitleaks ``sha256sum -c`` chain (which
# verifies the tarball against a hash we ship in the source tree)
# — a future hardening pass could pin the wheel SHA via
# ``pip install --require-hashes`` with a Sprint-2-owned
# ``semgrep-requirements.txt``.  Acceptable for now: the
# attack-surface delta is "PyPI account compromise" vs. "gitleaks
# release tag compromise", both of which our broader supply-chain
# strategy treats as upstream-trust failures.
ARG SEMGREP_VERSION=1.161.0

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

# ---------- Semgrep fetcher ----------
# Semgrep installs as a Python package; the simplest reproducible
# build pattern is a dedicated venv at ``/opt/semgrep`` (no
# collision with the worker's ``/app/.venv``).  The runtime stage
# copies the whole venv and symlinks the entry-point — Semgrep's
# own dependency tree (~50 MB) ends up isolated.
FROM ${PYTHON_IMAGE} AS semgrep-stage
ARG SEMGREP_VERSION
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
 && /opt/semgrep/bin/semgrep --version

# ---------- OSV-Scanner fetcher ----------
# Phase 3 Sprint 3.  osv-scanner ships as a bare Go binary on
# GitHub releases (no tarball wrapper), so the pattern is gitleaks
# minus the ``tar -xzf`` step.  ``curl -fsSL`` per CLAUDE.md §14;
# ``sha256sum -c`` against the upstream-published checksum is the
# integrity gate.
FROM ${PYTHON_IMAGE} AS osv-scanner-stage
ARG OSV_SCANNER_VERSION
ARG OSV_SCANNER_SHA256_AMD64
ARG OSV_SCANNER_SHA256_ARM64
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && ARCH="$(dpkg --print-architecture)" \
 && case "$ARCH" in \
      amd64) OSV_ARCH=linux_amd64; EXPECTED_SHA="${OSV_SCANNER_SHA256_AMD64}" ;; \
      arm64) OSV_ARCH=linux_arm64; EXPECTED_SHA="${OSV_SCANNER_SHA256_ARM64}" ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSLo /tmp/osv-scanner \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_ARCH}" \
 && echo "${EXPECTED_SHA}  /tmp/osv-scanner" | sha256sum -c - \
 && install -m 0755 /tmp/osv-scanner /usr/local/bin/osv-scanner \
 && /usr/local/bin/osv-scanner --version

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
# image lean.  Sprint 2 keeps the runtime image's apt surface
# unchanged from Sprint 1 — Semgrep is delivered as a venv
# (``/opt/semgrep``) copied from the semgrep-stage; no extra apt
# packages needed in runtime.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gitleaks-stage /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-scanner-stage /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner

# Copy the Semgrep venv as a self-contained tree, then symlink the
# entry-point into ``/usr/local/bin/`` so plugins can call
# ``semgrep`` without knowing the venv layout.  The venv carries
# its own Python interpreter (~5 MB) AND Semgrep's deps (~45 MB);
# total Sprint-2 image growth is roughly 50 MB.
COPY --from=semgrep-stage /opt/semgrep /opt/semgrep
RUN ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

WORKDIR /app
COPY --from=builder --chown=zynksec:zynksec /app /app

# ``COPY --chown`` sets ownership on COPIED files but NOT on the
# pre-existing ``/app`` directory itself (created by ``WORKDIR``
# under root).  Sprint 2 needs ``/app`` writable by ``zynksec``
# because Semgrep writes a per-process log directory at
# ``$HOME/.semgrep`` (and ``zynksec``'s home is ``/app`` per the
# useradd above).  Without this chown, semgrep crashes at startup
# with ``PermissionError: [Errno 13] Permission denied:
# '/app/.semgrep'``.
RUN chown zynksec:zynksec /app

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
