"""Factory that wires a :class:`GitleaksPlugin` from worker settings.

Sibling of :mod:`zynksec_worker.runners.zap_runner`.  CLAUDE.md §3 D —
Dependency Inversion: the Celery task imports
:class:`ScannerPlugin`, never :class:`GitleaksPlugin` directly; this
module is the only one in ``apps/worker`` that names the concrete
class.

No runtime config to thread through (gitleaks reads its built-in
rule set from the binary).  The function takes ``WorkerSettings``
on principle so the signature matches :func:`build_zap_plugin` —
adding a future ``gitleaks-config-path`` setting requires zero
caller changes.
"""

from __future__ import annotations

from zynksec_scanners.gitleaks import GitleaksPlugin

from zynksec_worker.config import WorkerSettings


def build_gitleaks_plugin(settings: WorkerSettings) -> GitleaksPlugin:
    """Build a :class:`GitleaksPlugin` from worker settings.

    The returned plugin shells out to the ``gitleaks`` CLI on
    PATH (installed by ``infra/docker/code-worker.Dockerfile``).
    Tests can override the path via constructor arg if they want
    to run against a non-default binary.
    """
    del settings  # gitleaks has no per-process config in Sprint 1
    return GitleaksPlugin()
