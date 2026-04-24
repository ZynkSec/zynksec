"""Scanner runner factories.

CLAUDE.md §3 (D — Dependency Inversion): the Celery task depends on
:class:`ScannerPlugin`, not on a concrete engine.  The factories in
this sub-package are the only modules that name :class:`ZapPlugin`
(or, in later phases, :class:`NucleiPlugin`, etc.).
"""

from zynksec_worker.runners.zap_runner import build_zap_plugin

__all__ = ["build_zap_plugin"]
