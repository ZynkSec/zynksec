"""Factory that wires a :class:`TrivyPlugin` from worker settings.

Sibling of :mod:`zynksec_worker.runners.osv_runner`.  CLAUDE.md
§3 D — Dependency Inversion: the Celery task imports
:class:`ScannerPlugin`, never :class:`TrivyPlugin` directly;
this module is the only one in ``apps/worker`` that names the
concrete class.

No runtime config to thread through (Trivy reads bundled
misconfig policies from the binary itself; ``--offline-scan``
guarantees no outbound calls).  The function takes
``WorkerSettings`` on principle so the signature matches its
sibling factories.
"""

from __future__ import annotations

from zynksec_scanners.trivy import TrivyPlugin

from zynksec_worker.config import WorkerSettings


def build_trivy_plugin(settings: WorkerSettings) -> TrivyPlugin:
    """Build a :class:`TrivyPlugin` from worker settings."""
    del settings  # trivy has no per-process config in Sprint 4
    return TrivyPlugin()
