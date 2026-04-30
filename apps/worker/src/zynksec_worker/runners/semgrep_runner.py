"""Factory that wires a :class:`SemgrepPlugin` from worker settings.

Sibling of :mod:`zynksec_worker.runners.gitleaks_runner`.  CLAUDE.md
§3 D — Dependency Inversion: the Celery task imports
:class:`ScannerPlugin`, never :class:`SemgrepPlugin` directly; this
module is the only one in ``apps/worker`` that names the concrete
class.

No runtime config to thread through (Semgrep reads
``p/security-audit`` from the upstream rule registry; offline-only
operation isn't supported in Sprint 2 — the binary fetches rules
on first use, then caches under ``$HOME/.semgrep``).  The function
takes ``WorkerSettings`` on principle so the signature matches its
sibling factories.
"""

from __future__ import annotations

from zynksec_scanners.semgrep import SemgrepPlugin

from zynksec_worker.config import WorkerSettings


def build_semgrep_plugin(settings: WorkerSettings) -> SemgrepPlugin:
    """Build a :class:`SemgrepPlugin` from worker settings."""
    del settings  # semgrep has no per-process config in Sprint 2
    return SemgrepPlugin()
