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
