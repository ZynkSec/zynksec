"""Scanner-plugin shared types.

Frozen dataclasses so the worker and plugins can pass structured state
around without needing Pydantic validation on every hop.  Real typed
contracts (as opposed to the Week-1 ``Any`` placeholders in
``base.py``) live here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

TargetKind = Literal["web_app", "api", "repo"]


@dataclass(frozen=True)
class Target:
    """Something a scanner runs against.

    In Phase 0 we scan a single URL at a time.  ``project_id`` and
    ``scan_id`` are carried on the target so :meth:`normalize` can
    compute the fingerprint without an extra argument thread.
    """

    kind: TargetKind
    url: str
    project_id: uuid.UUID
    scan_id: uuid.UUID


@dataclass(frozen=True)
class ScanContext:
    """Opaque handle returned by :meth:`ScannerPlugin.prepare`.

    The orchestrator passes it to :meth:`run`, :meth:`normalize`, and
    :meth:`teardown`.  Engines stash engine-native state in
    ``metadata`` (e.g. ZAP's scan id).  The dict is mutable-by-reference
    even though the dataclass is frozen — that's intentional; Phase 0
    keeps life simple by allowing plugins to record state as they go.
    """

    target: Target
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
