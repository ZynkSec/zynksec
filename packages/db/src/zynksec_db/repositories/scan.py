"""Scan repository — state-machine transitions."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.orm import Session

from zynksec_db.models.scan import Scan
from zynksec_db.repositories.base import Repository

_log = logging.getLogger(__name__)


class ScanRepository(Repository[Scan]):
    """State-machine transitions for :class:`Scan`.

    Each ``mark_*`` method is a single UPDATE + flush; the caller owns
    the transaction and decides whether to commit or roll back.
    """

    model = Scan

    def mark_running(self, session: Session, scan_id: uuid.UUID) -> Scan | None:
        """queued -> running.  Sets ``started_at = now()``."""
        session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status="running", started_at=datetime.now(UTC))
        )
        session.flush()
        return session.get(Scan, scan_id)

    def mark_completed(self, session: Session, scan_id: uuid.UUID) -> Scan | None:
        """running -> completed.  Sets ``completed_at = now()``."""
        session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status="completed", completed_at=datetime.now(UTC))
        )
        session.flush()
        return session.get(Scan, scan_id)

    def mark_failed(
        self,
        session: Session,
        scan_id: uuid.UUID,
        reason: str,
    ) -> Scan | None:
        """* -> failed.  ``reason`` is logged; a ``failure_reason`` column
        lands in Phase 1 when we persist the details.
        """
        _log.warning("scan.failed scan_id=%s reason=%s", scan_id, reason)
        session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status="failed", completed_at=datetime.now(UTC))
        )
        session.flush()
        return session.get(Scan, scan_id)
