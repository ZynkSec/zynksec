"""scan.run — the Phase-0 Week-2 no-op scan task.

Proves the API -> Celery -> Postgres -> API pipe works.  Week 3
replaces the 1-second sleep with a real :class:`ZapPlugin.run` call.

CLAUDE.md §5: the argument is a string UUID; the task re-fetches the
Scan row from the DB rather than receiving a rich object.
"""

from __future__ import annotations

import time
import uuid
from functools import lru_cache

import structlog
from celery import Task
from sqlalchemy.orm import Session, sessionmaker
from zynksec_db import ScanRepository, engine_from_url, make_session_factory

from zynksec_worker.celery_app import celery_app
from zynksec_worker.config import get_settings

_log = structlog.get_logger(__name__)
_repo = ScanRepository()


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    """Cache a single engine + session factory per worker process."""
    engine = engine_from_url(get_settings().database_url)
    return make_session_factory(engine)


@celery_app.task(name="scan.run", bind=True)
def run(self: Task, scan_id: str) -> None:
    """Mark running -> sleep 1s -> mark completed.

    On any exception the scan is marked ``failed`` with the message
    logged (a ``failure_reason`` column lands in Phase 1), and the
    original exception is re-raised so Celery records the failure.
    """

    del self  # Celery passes the Task instance; we don't use it here.
    scan_uuid = uuid.UUID(scan_id)
    _log.info("scan.run.start", scan_id=scan_id)

    factory = _session_factory()
    session = factory()
    try:
        _repo.mark_running(session, scan_uuid)
        session.commit()

        # Week 3: replace with ZapPlugin.prepare / run / normalize / teardown.
        time.sleep(1)

        _repo.mark_completed(session, scan_uuid)
        session.commit()
        _log.info("scan.run.complete", scan_id=scan_id)
    except Exception as exc:
        session.rollback()
        try:
            _repo.mark_failed(session, scan_uuid, reason=str(exc))
            session.commit()
        except Exception as secondary:  # noqa: BLE001 — best-effort bookkeeping
            session.rollback()
            _log.error(
                "scan.run.mark_failed_errored",
                scan_id=scan_id,
                error=str(secondary),
            )
        _log.error("scan.run.failed", scan_id=scan_id, error=str(exc))
        raise
    finally:
        session.close()
