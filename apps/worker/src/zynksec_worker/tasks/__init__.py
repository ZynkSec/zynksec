"""Celery task modules.  Imports register tasks with the Celery app.

Phase 2 Sprint 3 collapsed ``scan_group.process`` into per-child
``scan.run`` dispatch — there is no separate group-level task any
more.  Each child Scan rolls up its parent ScanGroup atomically
inside ``execute_scan`` (last child to terminate wins).
"""

from zynksec_worker.tasks import scan  # noqa: F401 — registers @task decorators

__all__ = ["scan"]
