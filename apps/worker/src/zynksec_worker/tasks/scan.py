"""scan.run — single-target scan task.

Walking-skeleton flow (docs/04 §0.9 steps 6-15).  The actual
execution work lives in :mod:`zynksec_worker.tasks._execution`,
shared with the Phase 2 Sprint 2 multi-target group task; this
module only carries the Celery task entry-point + arg parsing.

CLAUDE.md §5: the Celery arg is a string UUID.  Rich objects are
re-fetched from the DB inside the helper.
"""

from __future__ import annotations

import uuid

from celery import Task
from zynksec_schema import ScanProfile

from zynksec_worker.celery_app import celery_app
from zynksec_worker.tasks._execution import execute_scan


@celery_app.task(name="scan.run", bind=True)
def run(
    self: Task,
    scan_id: str,
    scan_profile: str = ScanProfile.PASSIVE.value,
    correlation_id: str | None = None,
) -> None:
    """Drive ZAP through one scan against one target.

    ``scan_profile`` arrives as a primitive (CLAUDE.md §5) — the wire
    form of :class:`ScanProfile`, e.g. ``"PASSIVE"``.  The default
    keeps task replays from older API versions safe.  ``correlation_id``
    is a Week-4 observability kwarg consumed by
    :func:`zynksec_worker.celery_app._bind_task_context` via the
    ``task_prerun`` signal; this function treats it as a no-op body
    parameter so Celery's argument-binding accepts it.

    Re-raises on failure so Celery records the task as failed —
    multi-target groups need a different policy (continue on per-
    child failure) and call :func:`execute_scan` directly.
    """
    del self, correlation_id
    scan_uuid = uuid.UUID(scan_id)
    profile = ScanProfile(scan_profile)
    completed = execute_scan(scan_uuid, profile)
    if not completed:
        # ``execute_scan`` already marked the row failed and logged
        # the cause; raising surfaces it as a Celery task failure
        # so retries / DLQ wiring (Phase 3+) can react.
        raise RuntimeError(f"scan {scan_id} failed; see structlog scan.run.failed line")
