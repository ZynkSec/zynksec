"""scan_group.process — multi-target scan group task.

Phase 2 Sprint 2: serial fan-out.  Iterates the group's children
in deterministic order (created_at ASC, id ASC tiebreaker) and
calls :func:`execute_scan` once per child against the existing
single-instance ZAP daemon.  Worker concurrency stays at 1 — true
parallel fan-out across multiple ZAP instances is Sprint 3.

Per-child failure policy: log the failure with the bound
``correlation_id`` + ``scan_id``, mark the child failed (which
``execute_scan`` already does internally), and continue to the next
child.  The group never aborts on a single bad scan; the rollup
status reflects the mix.

Group-status terminal mapping:

    every child completed      → ``completed``
    every child failed         → ``failed``
    mix of completed + failed  → ``partial_failure``

CLAUDE.md §5 — task args are primitives only (the group's id).
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
import structlog
from celery import Task
from sqlalchemy.orm import Session, sessionmaker
from zynksec_db import Scan, ScanGroup, ScanGroupRepository
from zynksec_schema import ScanProfile

from zynksec_worker.celery_app import celery_app
from zynksec_worker.tasks._execution import execute_scan, session_factory

_log = structlog.get_logger(__name__)
_group_repo = ScanGroupRepository()


def _list_child_ids(
    factory: sessionmaker[Session],
    scan_group_uuid: uuid.UUID,
) -> list[uuid.UUID]:
    """Return child Scan ids in the canonical iteration order.

    ``created_at ASC`` matches the order the API created the
    children in (one per ``target_ids`` list element).  ``id ASC``
    is the deterministic tiebreaker if two children share a
    timestamp (rare but possible at high precision).
    """
    with factory() as session:
        stmt = (
            sa.select(Scan.id)
            .where(Scan.scan_group_id == scan_group_uuid)
            .order_by(Scan.created_at.asc(), Scan.id.asc())
        )
        return list(session.execute(stmt).scalars().all())


def _load_group_profile(
    factory: sessionmaker[Session],
    scan_group_uuid: uuid.UUID,
) -> ScanProfile:
    """Read the group's ``scan_profile`` so each child runs at the
    same intensity the group was created at."""
    with factory() as session:
        group = session.get(ScanGroup, scan_group_uuid)
        if group is None:
            raise RuntimeError(f"ScanGroup {scan_group_uuid} vanished between enqueue and dispatch")
        return ScanProfile(group.scan_profile)


def _mark_running(factory: sessionmaker[Session], scan_group_uuid: uuid.UUID) -> None:
    with factory() as session:
        try:
            _group_repo.mark_running(session, scan_group_uuid)
            session.commit()
        except Exception:
            session.rollback()
            raise


def _mark_terminal(
    factory: sessionmaker[Session],
    scan_group_uuid: uuid.UUID,
    *,
    status: str,
) -> None:
    with factory() as session:
        try:
            _group_repo.mark_terminal(session, scan_group_uuid, status=status)
            session.commit()
        except Exception:
            session.rollback()
            raise


def _terminal_status(completed: int, failed: int) -> str:
    """Roll up child results into the group's terminal state.

    Both buckets non-zero → partial_failure.  Otherwise the
    surviving bucket wins.  Zero children of either is impossible
    if the group was created via ``POST /scan-groups`` (Pydantic
    enforces ``min_length=1``); the conditional just guards
    operationally-pathological cases (manual DB poking, etc.).
    """
    if completed > 0 and failed > 0:
        return "partial_failure"
    if failed > 0:
        return "failed"
    return "completed"


@celery_app.task(name="scan_group.process", bind=True)
def process(
    self: Task,
    scan_group_id: str,
    correlation_id: str | None = None,
) -> None:
    """Drive every child of the named ScanGroup, serially.

    ``correlation_id`` is consumed by the ``task_prerun`` signal
    in :mod:`zynksec_worker.celery_app`; this function treats it
    as a no-op so Celery's arg-binding accepts the kwarg.
    ``execute_scan`` binds an additional ``scan_id`` contextvar
    per child so log filtering by scan stays clean.
    """
    del self, correlation_id
    scan_group_uuid = uuid.UUID(scan_group_id)
    factory = session_factory()

    structlog.contextvars.bind_contextvars(scan_group_id=scan_group_id)
    try:
        _log.info("scan_group.process.start", scan_group_id=scan_group_id)

        profile = _load_group_profile(factory, scan_group_uuid)
        child_ids = _list_child_ids(factory, scan_group_uuid)

        _mark_running(factory, scan_group_uuid)
        _log.info(
            "scan_group.process.children_listed",
            scan_group_id=scan_group_id,
            child_count=len(child_ids),
            scan_profile=profile.value,
        )

        completed = 0
        failed = 0
        for child_id in child_ids:
            try:
                ok = execute_scan(child_id, profile)
            except Exception as exc:  # noqa: BLE001 — group must not abort
                # ``execute_scan`` already catches its own exceptions;
                # this is defense in depth for anything escaping the
                # helper (e.g. SQLAlchemy connection errors during
                # the status-mark write).
                _log.exception(
                    "scan_group.child.unexpected_error",
                    scan_group_id=scan_group_id,
                    scan_id=str(child_id),
                    error=str(exc),
                )
                failed += 1
                continue
            if ok:
                completed += 1
            else:
                failed += 1

        terminal = _terminal_status(completed, failed)
        _mark_terminal(factory, scan_group_uuid, status=terminal)
        _log.info(
            "scan_group.process.complete",
            scan_group_id=scan_group_id,
            terminal_status=terminal,
            completed=completed,
            failed=failed,
        )
    finally:
        structlog.contextvars.unbind_contextvars("scan_group_id")
