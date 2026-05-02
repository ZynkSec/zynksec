"""Scanner runner factories.

CLAUDE.md §3 (D — Dependency Inversion): the Celery task depends on
:class:`ScannerPlugin`, not on a concrete engine.  The factories in
this sub-package are the only modules that name :class:`ZapPlugin`,
:class:`GitleaksPlugin`, :class:`SemgrepPlugin`, or any other
concrete plugin class.

Two dispatchers live here:

  * :func:`build_plugin_by_name(name, settings)` — Phase 3 Sprint 2:
    given an already-resolved scanner name (the API resolves
    ``scan.scanner`` against the registry at write-time and persists
    the resolved name back to the DB), return the matching plugin
    instance.  The worker prefers this path because it doesn't have
    to re-resolve registry state.

  * :func:`build_plugin_for(kind, settings)` — Sprint 1 backward-
    compat shim.  Resolves ``kind`` to the per-kind default
    scanner via :func:`zynksec_scanners.scanner_for_kind`, then
    delegates to :func:`build_plugin_by_name`.  Existing callers
    that haven't migrated to passing the scanner name explicitly
    keep working.

Adding a new scanner family is a one-line edit in
:func:`build_plugin_by_name` plus a new ``build_<family>_plugin``
factory module.
"""

from __future__ import annotations

from zynksec_scanners import (
    SCANNER_GITLEAKS,
    SCANNER_OSV,
    SCANNER_SEMGREP,
    SCANNER_ZAP,
    ScannerPlugin,
    TargetKind,
    scanner_for_kind,
)

from zynksec_worker.config import WorkerSettings
from zynksec_worker.runners.gitleaks_runner import build_gitleaks_plugin
from zynksec_worker.runners.osv_runner import build_osv_plugin
from zynksec_worker.runners.semgrep_runner import build_semgrep_plugin
from zynksec_worker.runners.zap_runner import build_zap_plugin


def build_plugin_by_name(name: str, settings: WorkerSettings) -> ScannerPlugin:
    """Return a fresh :class:`ScannerPlugin` for an already-resolved
    scanner name.

    Raises :class:`KeyError` for names that don't have a runner
    factory wired up — that's a registry-vs-runners mismatch and
    should fail loudly.
    """
    if name == SCANNER_ZAP:
        return build_zap_plugin(settings)
    if name == SCANNER_GITLEAKS:
        return build_gitleaks_plugin(settings)
    if name == SCANNER_SEMGREP:
        return build_semgrep_plugin(settings)
    if name == SCANNER_OSV:
        return build_osv_plugin(settings)
    raise KeyError(f"no plugin builder registered for scanner {name!r}")


def build_plugin_for(kind: TargetKind, settings: WorkerSettings) -> ScannerPlugin:
    """Sprint 1 compat shim — resolve kind to the default scanner name,
    then delegate to :func:`build_plugin_by_name`.

    Sprint-2+ callers should pass the scanner name explicitly via
    :func:`build_plugin_by_name` so a per-scan ``scanner`` override
    flows through.
    """
    return build_plugin_by_name(scanner_for_kind(kind), settings)


__all__ = [
    "build_gitleaks_plugin",
    "build_osv_plugin",
    "build_plugin_by_name",
    "build_plugin_for",
    "build_semgrep_plugin",
    "build_zap_plugin",
]
