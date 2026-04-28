"""Target repository — list-by-project + scan-link reference count."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zynksec_db.models.scan import Scan
from zynksec_db.models.target import Target
from zynksec_db.repositories.base import Repository


class TargetRepository(Repository[Target]):
    """CRUD + scan-reference checks for :class:`Target`."""

    model = Target

    def list_by_project(
        self,
        session: Session,
        project_id: uuid.UUID,
    ) -> list[Target]:
        """Return all Targets in a project, ordered by ``created_at`` ASC.

        Stable ordering matters because the integration test creates
        multiple Targets and asserts they show up in the order they
        were added; otherwise the test would be flaky on Postgres
        (which has no implicit row order).
        """
        stmt = (
            select(Target).where(Target.project_id == project_id).order_by(Target.created_at.asc())
        )
        return list(session.execute(stmt).scalars().all())

    def delete(self, session: Session, target_id: uuid.UUID) -> bool:
        """Delete the Target.  Returns ``True`` if a row was removed.

        Caller is expected to have already verified that no scans
        reference this target (via :meth:`scan_count`); the FK on
        ``scans.target_id`` is ``ON DELETE RESTRICT`` so calling this
        on a referenced Target raises ``IntegrityError`` from the DB.
        That's the safety belt — :meth:`scan_count` is the polite
        pre-check.
        """
        target = session.get(Target, target_id)
        if target is None:
            return False
        session.delete(target)
        session.flush()
        return True

    def scan_count(self, session: Session, target_id: uuid.UUID) -> int:
        """Number of scans currently referencing this target.

        The DELETE handler reads this and surfaces it as the canonical
        409 ``target_has_scans`` error rather than letting the
        ``IntegrityError`` from the FK leak through.
        """
        stmt = select(func.count()).select_from(Scan).where(Scan.target_id == target_id)
        return int(session.execute(stmt).scalar_one())
