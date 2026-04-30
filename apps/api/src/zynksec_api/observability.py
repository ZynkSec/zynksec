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
- ``include_local_variables=False`` (Phase 3 Sprint 1 security
  hardening): Sentry's default is to ship every frame's local
  variables along with exception events.  For the worker that means
  any exception fired during a gitleaks scan would upload the
  ``findings`` list — including ``GitleaksFinding(raw_secret=...)``
  fields with plaintext credentials — to the Sentry/GlitchTip DSN.
  Disabled across both processes (api + worker) so the leak surface
  is closed at the source.  ``_before_send`` ALSO scrubs any
  ``vars`` block that survives (e.g. via a future config flip) as
  belt-and-braces defence.
- ``before_send`` attaches the current structlog ``correlation_id``
  as a tag on every event so captured errors can be cross-referenced
  against logs.  It also redacts secret-named locals on the way out.
- Idempotent: safe to call from ``__init__.py`` and from tests.
"""

from __future__ import annotations

import os
from typing import Any

_SENTRY_INITIALISED = False

#: Local-variable keys whose values should never reach the Sentry
#: backend.  Match is case-insensitive substring — ``raw_secret``,
#: ``user_password``, ``api_key`` all hit.  Belt-and-braces defence
#: paired with ``include_local_variables=False`` (which removes the
#: vars dict entirely on most events); a future config flip that
#: re-enables locals still gets the scrub.
_SECRET_VAR_NAME_FRAGMENTS: frozenset[str] = frozenset(
    {
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "match",  # gitleaks JSON ``Match`` field carries plaintext
    }
)
_SCRUBBED: str = "[Filtered]"


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
        # Closes the plaintext-secrets-in-locals leak path described
        # in the module docstring.  The worker's gitleaks plugin
        # holds raw-secret values on ``GitleaksFinding`` dataclasses
        # for the duration of ``execute_scan``; without this, a DB
        # blip during the find-persistence loop would ship every
        # plaintext to telemetry.
        include_local_variables=False,
    )
    sentry_sdk.set_tag("service", service)
    _SENTRY_INITIALISED = True
    return True


def _scrub_frame_vars(frames: list[dict[str, Any]]) -> None:
    """Redact secret-named keys in every frame's ``vars`` dict.

    Mutates ``frames`` in place — Sentry's event dict structure is
    documented as mutable inside ``before_send``.  A frame may have
    no ``vars`` (e.g. when ``include_local_variables=False``); skip
    silently.  Match is case-insensitive substring against
    :data:`_SECRET_VAR_NAME_FRAGMENTS`.
    """
    for frame in frames:
        frame_vars = frame.get("vars")
        if not isinstance(frame_vars, dict):
            continue
        for key in list(frame_vars.keys()):
            key_lc = key.lower()
            if any(fragment in key_lc for fragment in _SECRET_VAR_NAME_FRAGMENTS):
                frame_vars[key] = _SCRUBBED


def _before_send(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any] | None:
    """Attach correlation_id and redact secret-named frame variables.

    Two responsibilities:
      1. Tag the event with the current structlog ``correlation_id``
         so captured errors can be cross-referenced against logs.
      2. Walk every stack-frame's ``vars`` dict and redact keys
         matching :data:`_SECRET_VAR_NAME_FRAGMENTS`.  Defence in
         depth: ``sentry_sdk.init(include_local_variables=False)``
         normally drops the vars dict entirely, but a future config
         change or a Sentry SDK default flip would re-enable it.
         The scrub means a re-enable never silently re-opens the
         leak path.
    """
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

    try:
        for exc_value in event.get("exception", {}).get("values", []) or []:
            stacktrace = exc_value.get("stacktrace") or {}
            frames = stacktrace.get("frames") or []
            if isinstance(frames, list):
                _scrub_frame_vars(frames)
        # Threads (non-exception events from sentry's profiler /
        # threading integration) carry the same shape under
        # ``threads.values``.  Scrub there too.
        for thread in event.get("threads", {}).get("values", []) or []:
            stacktrace = thread.get("stacktrace") or {}
            frames = stacktrace.get("frames") or []
            if isinstance(frames, list):
                _scrub_frame_vars(frames)
    except Exception:  # noqa: BLE001, S110 — observability hook must never crash callers
        pass

    return event
