"""Sentry SDK initialisation for GlitchTip-compatible error capture.

Kept minimal and dependency-light so it can run as the very first
thing at module import — BEFORE any zynksec code that might raise.
Reads the DSN straight from os.environ rather than through
``pydantic-settings`` so pulling in the config layer doesn't force
an import chain before Sentry is armed.

Contract:
- No-ops when neither ``SENTRY_DSN`` nor ``GLITCHTIP_DSN`` is set, so
  boot is identical with or without GlitchTip running.  Production
  deployments without a DSN must not log warnings every request.
- ``traces_sample_rate=0.0``: no APM in Phase 0.  Adding tracing is a
  separate decision (docs/04 future phase).
- ``before_send`` attaches the current structlog ``correlation_id``
  as a tag on every event so captured errors can be cross-referenced
  against logs.
- Idempotent: safe to call from ``__init__.py`` and from tests.
"""

from __future__ import annotations

import os
from typing import Any

_SENTRY_INITIALISED = False


def init_sentry(service: str) -> bool:
    """Initialise Sentry for this process, or no-op if no DSN is set.

    Returns True if Sentry was actually initialised, False otherwise.
    ``service`` ("api" / "worker") is set as a tag on every event so
    captured errors can be filtered per process type.
    """
    global _SENTRY_INITIALISED
    if _SENTRY_INITIALISED:
        return True

    dsn = (os.environ.get("SENTRY_DSN") or os.environ.get("GLITCHTIP_DSN") or "").strip()
    if not dsn:
        return False

    try:
        import sentry_sdk
    except ImportError:
        # Package missing in dev machines without the full extras
        # installed — fall back to no-op rather than crashing boot.
        return False

    integrations: list[Any] = []
    try:
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration

        integrations.extend([StarletteIntegration(), FastApiIntegration()])
    except ImportError:
        pass

    sentry_sdk.init(
        dsn=dsn,
        environment=os.environ.get("ZYNKSEC_ENV", "dev"),
        traces_sample_rate=0.0,
        integrations=integrations,
        before_send=_before_send,
        send_default_pii=False,
    )
    sentry_sdk.set_tag("service", service)
    _SENTRY_INITIALISED = True
    return True


def _before_send(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any] | None:
    """Attach the current ``correlation_id`` to every outgoing event."""
    del hint
    try:
        import structlog

        bound = structlog.contextvars.get_contextvars()
        if isinstance(bound, dict):
            correlation_id = bound.get("correlation_id")
            if correlation_id:
                tags = event.setdefault("tags", {})
                tags["correlation_id"] = str(correlation_id)
    except Exception:  # noqa: BLE001, S110 — observability hook must never crash callers
        pass
    return event
