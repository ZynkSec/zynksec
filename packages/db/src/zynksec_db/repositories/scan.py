"""Scan repository — state-machine transitions."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, union_all, update
from sqlalchemy.orm import Session

from zynksec_db.models.code_finding import CodeFinding
from zynksec_db.models.finding import Finding
from zynksec_db.models.scan import Scan
from zynksec_db.repositories.base import Repository

_log = logging.getLogger(__name__)


class ScanRepository(Repository[Scan]):
    """State-machine transitions for :class:`Scan`.

    Each ``mark_*`` method is a single UPDATE + flush; the caller owns
    the transaction and decides whether to commit or roll back.
    """

    model = Scan

    def list_by_project(
        self,
        session: Session,
        project_id: uuid.UUID,
    ) -> list[tuple[Scan, int]]:
        """Return every scan in a project with its total findings count,
        newest first.

        Phase 4 Sprint 1.  Powers ``GET /api/v1/scans``.  The
        ``findings_count`` is the sum of ``findings`` (ZAP, HTTP-shaped)
        and ``code_findings`` (gitleaks / semgrep / osv-scanner / trivy,
        file-shaped) rows owned by each scan.

        Implemented as one query per family folded into a single
        ``UNION ALL`` aggregate so the list endpoint stays at O(1) DB
        round-trips regardless of how many scans the project has —
        no N+1 even with 100k scans.  Newest-first ordering by
        ``created_at DESC`` matches what
        :func:`ScanGroupRepository.list_by_project` does.
        """
        # Count rows in both finding tables per scan_id, then UNION
        # ALL them so the outer aggregate adds the two contributions
        # together.  COALESCE keeps the LEFT JOIN result as 0 for
        # scans with no findings of either kind (rather than NULL
        # tripping the int cast in the read model).
        finding_counts = select(Finding.scan_id.label("scan_id"), func.count().label("n")).group_by(
            Finding.scan_id
        )
        code_finding_counts = select(
            CodeFinding.scan_id.label("scan_id"), func.count().label("n")
        ).group_by(CodeFinding.scan_id)
        unioned = union_all(finding_counts, code_finding_counts).subquery("c")
        totals = (
            select(unioned.c.scan_id, func.sum(unioned.c.n).label("total"))
            .group_by(unioned.c.scan_id)
            .subquery("t")
        )
        stmt = (
            select(Scan, func.coalesce(totals.c.total, 0).label("findings_count"))
            .outerjoin(totals, totals.c.scan_id == Scan.id)
            .where(Scan.project_id == project_id)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
        )
        rows = session.execute(stmt).all()
        return [(scan, int(count)) for scan, count in rows]

    def list_by_group(
        self,
        session: Session,
        scan_group_id: uuid.UUID,
    ) -> list[Scan]:
        """Return every child scan of a group, ordered by ``(created_at, id)``.

        The deterministic ordering matches what the worker iterates
        in and what the API echoes via ``child_scan_ids`` /
        ``child_scans`` so a client traversing either list reads
        the same children in the same order.
        """
        stmt = (
            select(Scan)
            .where(Scan.scan_group_id == scan_group_id)
            .order_by(Scan.created_at.asc(), Scan.id.asc())
        )
        return list(session.execute(stmt).scalars().all())

    def total_count(self, session: Session) -> int:
        """``COUNT(*) FROM scans`` — used by the legacy POST rotation cursor.

        Phase 2 Sprint 3's legacy single-scan path picks the per-pair
        queue via ``(count % N) + 1``; the cursor's "restart-safe"
        character (no extra table, no Redis counter) depends on this
        count being read inside the same transaction as the INSERT,
        so two concurrent POSTs see consistent neighbours.  Pushing
        the count into the repo keeps the router free of raw SQL
        (CLAUDE.md §3) without changing the cursor's semantics.
        """
        stmt = select(func.count(Scan.id))
        return int(session.execute(stmt).scalar_one() or 0)

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
        """* -> failed.  Persists ``reason`` on the row and logs it.

        The log line stays so failures are visible without a DB query;
        the column makes the same string available to any client of the
        scan via the API response (``ScanRead.failure_reason``).
        """
        _log.warning("scan.failed scan_id=%s reason=%s", scan_id, reason)
        session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                status="failed",
                completed_at=datetime.now(UTC),
                failure_reason=reason,
            )
        )
        session.flush()
        return session.get(Scan, scan_id)
