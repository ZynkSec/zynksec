"""Sentry SDK initialisation for the Celery worker process.

Mirror of ``apps/api/.../observability.py`` — same contract, same
env-var names, same no-op-when-unset behaviour.  Uses the Celery
integration so Celery's own task lifecycle events (retries, failures,
worker shutdown) land in GlitchTip.

docs/04 §0.14 will promote both copies into ``packages/shared-schema``
once the sentry-sdk version pin stabilises; until then the two files
stay in sync by hand.
"""

from __future__ import annotations

import os
from typing import Any

_SENTRY_INITIALISED = False


def init_sentry(service: str) -> bool:
    """Initialise Sentry for this process, or no-op if no DSN is set."""
    global _SENTRY_INITIALISED
    if _SENTRY_INITIALISED:
        return True

    dsn = (os.environ.get("SENTRY_DSN") or os.environ.get("GLITCHTIP_DSN") or "").strip()
    if not dsn:
        return False

    try:
        import sentry_sdk
    except ImportError:
        return False

    integrations: list[Any] = []
    try:
        from sentry_sdk.integrations.celery import CeleryIntegration

        integrations.append(CeleryIntegration())
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
