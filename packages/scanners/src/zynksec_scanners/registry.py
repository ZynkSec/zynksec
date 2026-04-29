"""Static map: ``TargetKind`` -> name of the scanner family that owns it.

Phase 3 Sprint 1 introduces the second scanner family (gitleaks)
alongside ZAP.  The dispatch question — "which Celery queue does
this Target's kind route to, and which plugin runs it?" — needs
ONE source of truth that the API + worker both read.

Intentionally tiny: a dict keyed by :class:`TargetKind`.  Adding a
new scanner family (semgrep, trivy, OSV, ...) is one row here plus
the worker-side runner registration.

Why not a class hierarchy?  A registry of ``Type[ScannerPlugin]``
would couple this module to every plugin's import graph (so
``apps/api`` would suddenly need the worker's ZAP client + the
code-worker's gitleaks dependency).  A name-only registry keeps
the API package import-light and lets each app wire its own
plugin instances.
"""

from __future__ import annotations

from zynksec_scanners.types import TargetKind

#: Scanner family names — opaque tokens compared by string equality.
#: The worker turns these into concrete plugin instances; the API
#: turns them into Celery queue names via :mod:`zynksec_schema.queues`.
SCANNER_ZAP: str = "zap"
SCANNER_GITLEAKS: str = "gitleaks"


_SCANNER_BY_TARGET_KIND: dict[TargetKind, str] = {
    "web_app": SCANNER_ZAP,
    # ``api`` Targets are still served by ZAP today (it scans the
    # OpenAPI spec via the same daemon); a dedicated API-fuzz
    # scanner is Phase 3+ scope.  Routing them to the ZAP queue
    # preserves the existing behaviour while leaving the registry
    # ready for a future scanner-id swap.
    "api": SCANNER_ZAP,
    "repo": SCANNER_GITLEAKS,
}


def scanner_for_kind(kind: TargetKind) -> str:
    """Return the scanner-family name that owns this target kind.

    Raises :class:`KeyError` for unknown kinds — the schema enum
    constrains inputs at the API boundary, so a miss here is a
    legitimate misconfiguration that should fail loudly rather
    than silently fall back to ZAP.
    """
    return _SCANNER_BY_TARGET_KIND[kind]
