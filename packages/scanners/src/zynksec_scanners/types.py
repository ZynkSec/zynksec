"""Scanner-plugin shared types.

Frozen dataclasses so the worker and plugins can pass structured state
around without needing Pydantic validation on every hop.  Real typed
contracts (as opposed to the Week-1 ``Any`` placeholders in
``base.py``) live here.

:class:`ScanProfile` lives in :mod:`zynksec_schema` (the single source
of truth shared by the API request body, the worker task signature,
and this plugin contract) and is re-exported here so existing imports
``from zynksec_scanners import ScanProfile`` keep working.

Phase 2 Sprint 1 renamed the runtime parameter bundle from ``Target``
to :class:`ScanTarget` so the bare name ``Target`` is free for the
new persistent ``Target`` ORM resource (in :mod:`zynksec_db`) that the
API exposes via ``/api/v1/targets``.  ``Target`` remains as a
deprecation alias here so out-of-tree plugins keep importing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from zynksec_schema import ScanProfile

TargetKind = Literal["web_app", "api", "repo"]

__all__ = [
    "HealthStatus",
    "RawScanResult",
    "ScanContext",
    "ScanProfile",
    "ScanTarget",
    "Target",
    "TargetKind",
]


@dataclass(frozen=True)
class ScanTarget:
    """Runtime parameter bundle handed to a :class:`ScannerPlugin`.

    NOT a persistent resource — this is the per-scan dataclass the
    worker constructs and passes to ``plugin.prepare``/``run``/etc.
    The persistent user-facing resource is
    :class:`zynksec_db.Target` (Phase 2 Sprint 1+).

    ``project_id`` and ``scan_id`` are carried on the bundle so
    :meth:`normalize` can compute the fingerprint without an extra
    argument thread.  ``scan_profile`` selects the engine's intensity.
    """

    kind: TargetKind
    url: str
    project_id: uuid.UUID
    scan_id: uuid.UUID
    scan_profile: ScanProfile = ScanProfile.PASSIVE


# DEPRECATED: renamed to ScanTarget in Phase 2 Sprint 1; alias removed
# once all out-of-tree plugins migrate.  In-tree code uses ScanTarget.
Target = ScanTarget


@dataclass(frozen=True)
class ScanContext:
    """Opaque handle returned by :meth:`ScannerPlugin.prepare`.

    The orchestrator passes it to :meth:`run`, :meth:`normalize`, and
    :meth:`teardown`.  Engines stash engine-native state in
    ``metadata`` (e.g. ZAP's scan id).  The dict is mutable-by-reference
    even though the dataclass is frozen — that's intentional; Phase 0
    keeps life simple by allowing plugins to record state as they go.
    """

    target: ScanTarget
    engine_scan_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawScanResult:
    """Engine-native output.  Never shown to users (CLAUDE.md §5)."""

    engine: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class HealthStatus:
    """Engine liveness report returned by :meth:`health_check`."""

    ok: bool
    engine_version: str | None = None
    message: str | None = None
