"""ScanGroup repository — CRUD + status transitions for the multi-
target scan parent row (Phase 2 Sprint 2).

Children of a group are :class:`Scan` rows; reading a group's
children is :class:`ScanRepository.list(scan_group_id=...)`.  The
canonical "what status are this group's children in" rollup is
computed by the API layer at GET time (not stored on the group row)
— see :mod:`zynksec_db.models.scan_group` docstring for why.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy.orm import Session

from zynksec_db.models.scan_group import ScanGroup
from zynksec_db.repositories.base import Repository

_log = logging.getLogger(__name__)


class ScanGroupRepository(Repository[ScanGroup]):
    """CRUD + status transitions for :class:`ScanGroup`."""

    model = ScanGroup

    def list_by_project(
        self,
        session: Session,
        project_id: uuid.UUID,
    ) -> list[ScanGroup]:
        """Return all ScanGroups in a project, newest first.

        Newest-first matches the ``ix_scan_groups_project_id_created_at``
        index ordering and is what a UI listing recently-launched
        sweeps would want by default.
        """
        stmt = (
            sa.select(ScanGroup)
            .where(ScanGroup.project_id == project_id)
            .order_by(ScanGroup.created_at.desc())
        )
        return list(session.execute(stmt).scalars().all())

    def update_status(
        self,
        session: Session,
        scan_group_id: uuid.UUID,
        *,
        status: str,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> ScanGroup | None:
        """Transition the group's status + optional timestamp set.

        ``started_at`` / ``completed_at`` are caller-supplied because
        the worker is the source of truth for those moments (vs.
        relying on ``func.now()`` in the DB, which would shift if
        we ever moved to logical replication).  Caller owns the
        transaction and decides when to commit.
        """
        values: dict[str, object] = {"status": status}
        if started_at is not None:
            values["started_at"] = started_at
        if completed_at is not None:
            values["completed_at"] = completed_at
        session.execute(sa.update(ScanGroup).where(ScanGroup.id == scan_group_id).values(**values))
        session.flush()
        return session.get(ScanGroup, scan_group_id)

    def mark_running(self, session: Session, scan_group_id: uuid.UUID) -> ScanGroup | None:
        """queued -> running.  Sets ``started_at = now()``."""
        return self.update_status(
            session,
            scan_group_id,
            status="running",
            started_at=datetime.now(UTC),
        )

    def mark_running_if_queued(self, session: Session, scan_group_id: uuid.UUID) -> bool:
        """Idempotent ``queued -> running`` for parallel-child dispatch.

        Phase 2 Sprint 3 dispatches each ScanGroup child as its own
        Celery task that runs in parallel on a worker/ZAP pair.  The
        first child to start needs to flip the parent group from
        ``queued`` to ``running``; the second / third / Nth child
        finds it already running and must NOT roll back the
        ``started_at`` timestamp.

        Implementation: a single ``UPDATE ... WHERE status = 'queued'``
        — Postgres makes the row-level lock + write atomic, so two
        children racing both attempt the update but only one writes
        and the other no-ops cleanly (zero rows matched).  No
        ``SELECT FOR UPDATE`` needed; no application-level lock
        either.

        Returns ``True`` if this call was the one that flipped the
        status (useful for "only the first child logs the transition"
        diagnostics); ``False`` if the group was already running or
        already terminal.  Caller owns the transaction.
        """
        result = session.execute(
            sa.update(ScanGroup)
            .where(ScanGroup.id == scan_group_id, ScanGroup.status == "queued")
            .values(status="running", started_at=datetime.now(UTC))
        )
        session.flush()
        return bool(result.rowcount)

    def mark_terminal(
        self,
        session: Session,
        scan_group_id: uuid.UUID,
        *,
        status: str,
    ) -> ScanGroup | None:
        """Set a terminal status (``completed`` / ``failed`` /
        ``partial_failure``) and ``completed_at = now()``.  Caller
        decides which status based on the rollup of child scans.
        """
        if status not in {"completed", "failed", "partial_failure"}:
            raise AssertionError(f"non-terminal status passed to mark_terminal: {status!r}")
        return self.update_status(
            session,
            scan_group_id,
            status=status,
            completed_at=datetime.now(UTC),
        )

    def mark_terminal_if_all_children_done(
        self,
        session: Session,
        scan_group_id: uuid.UUID,
    ) -> str | None:
        """Atomically promote group to terminal iff every child is terminal.

        Phase 2 Sprint 3: parallel-child dispatch means there's no
        coordinator task to roll up the group.  Each child, after
        marking itself terminal, calls this method; only the LAST
        child (the one that observes no non-terminal sibling) wins
        and flips the group's status.

        The atomicity comes from a single CTE+UPDATE: we count
        completed / failed / pending children and (in the same
        statement) UPDATE the group only if pending == 0 AND the
        group is still non-terminal.  Two children racing past their
        own status commits both run the query, but Postgres's
        snapshot isolation + the ``status IN ('queued','running')``
        guard mean only one row gets updated — the other observes
        the post-update state and matches zero rows.

        Returns the terminal status that was set (``"completed"`` /
        ``"failed"`` / ``"partial_failure"``), or ``None`` if the
        group was either still pending or already terminal at the
        moment the query ran.  Caller owns the transaction.
        """
        # Single round-trip: a CTE counts each child-status bucket,
        # then the UPDATE conditionally promotes the group.  CASE
        # picks the terminal label from the counts: any failed +
        # any completed -> partial_failure; all failed -> failed;
        # all completed -> completed.
        sql = sa.text(
            """
            WITH counts AS (
                SELECT
                    COUNT(*) FILTER (WHERE status = 'completed') AS completed,
                    COUNT(*) FILTER (WHERE status = 'failed')    AS failed,
                    COUNT(*) FILTER (WHERE status NOT IN ('completed', 'failed'))
                                                                  AS pending
                FROM scans
                WHERE scan_group_id = :group_id
            )
            UPDATE scan_groups sg
            SET
                status = CASE
                    WHEN c.failed = 0    THEN 'completed'
                    WHEN c.completed = 0 THEN 'failed'
                    ELSE                       'partial_failure'
                END,
                completed_at = now(),
                updated_at   = now()
            FROM counts c
            WHERE sg.id = :group_id
              AND sg.status IN ('queued', 'running')
              AND c.pending = 0
            RETURNING sg.status;
            """
        )
        row = session.execute(sql, {"group_id": scan_group_id}).first()
        session.flush()
        if row is None:
            return None
        return str(row[0])
