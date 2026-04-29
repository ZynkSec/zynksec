"""Scanner runner factories.

CLAUDE.md §3 (D — Dependency Inversion): the Celery task depends on
:class:`ScannerPlugin`, not on a concrete engine.  The factories in
this sub-package are the only modules that name :class:`ZapPlugin`,
:class:`GitleaksPlugin`, or any other concrete plugin class.

The :func:`build_plugin_for` dispatcher reads the canonical
``TargetKind -> scanner-family`` map from
:mod:`zynksec_scanners.registry` and returns the matching plugin
instance.  The Celery task calls this helper instead of naming a
concrete factory directly so adding a new scanner family is a
one-line edit here plus a new ``build_<family>_plugin`` factory.
"""

from __future__ import annotations

from zynksec_scanners import (
    SCANNER_GITLEAKS,
    SCANNER_ZAP,
    ScannerPlugin,
    TargetKind,
    scanner_for_kind,
)

from zynksec_worker.config import WorkerSettings
from zynksec_worker.runners.gitleaks_runner import build_gitleaks_plugin
from zynksec_worker.runners.zap_runner import build_zap_plugin


def build_plugin_for(kind: TargetKind, settings: WorkerSettings) -> ScannerPlugin:
    """Return a fresh :class:`ScannerPlugin` for this target kind.

    Raises :class:`KeyError` for unknown kinds (canonical
    misconfiguration — the schema enum already constrains inputs at
    the API boundary, so missing here means the registry got out of
    sync with the enum and we want to fail loudly).
    """
    family = scanner_for_kind(kind)
    if family == SCANNER_ZAP:
        return build_zap_plugin(settings)
    if family == SCANNER_GITLEAKS:
        return build_gitleaks_plugin(settings)
    raise KeyError(f"no plugin builder registered for scanner family {family!r}")


__all__ = ["build_gitleaks_plugin", "build_plugin_for", "build_zap_plugin"]
