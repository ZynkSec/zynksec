"""Factory that wires an :class:`OsvScannerPlugin` from worker settings.

Sibling of :mod:`zynksec_worker.runners.semgrep_runner`.  CLAUDE.md
§3 D — Dependency Inversion: the Celery task imports
:class:`ScannerPlugin`, never :class:`OsvScannerPlugin` directly;
this module is the only one in ``apps/worker`` that names the
concrete class.

No runtime config to thread through (osv-scanner queries
``api.osv.dev`` directly; offline operation isn't supported in
Sprint 3).  The function takes ``WorkerSettings`` on principle so
the signature matches its sibling factories.
"""

from __future__ import annotations

from zynksec_scanners.osv import OsvScannerPlugin

from zynksec_worker.config import WorkerSettings


def build_osv_plugin(settings: WorkerSettings) -> OsvScannerPlugin:
    """Build an :class:`OsvScannerPlugin` from worker settings."""
    del settings  # osv-scanner has no per-process config in Sprint 3
    return OsvScannerPlugin()
