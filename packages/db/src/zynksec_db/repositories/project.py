"""Project repository — name lookup for the implicit Local Dev fallback.

Phase 0 has no project-create HTTP endpoint; the implicit "Local Dev"
project (docs/04 §0.16) is created on first request.  The lookup-by-
name SQL used to live in the API's project-resolution helper as
``session.execute(select(Project).where(Project.name == ...))`` —
moving it here lets the router drop the last raw SQL hit
(CLAUDE.md §3).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from zynksec_db.models.project import Project
from zynksec_db.repositories.base import Repository


class ProjectRepository(Repository[Project]):
    """CRUD + name lookup for :class:`Project`."""

    model = Project

    def get_by_name(self, session: Session, name: str) -> Project | None:
        """Return the project named ``name`` or ``None`` if absent.

        Used by the project-resolution helper to look up the implicit
        Local Dev project; the helper composes ``get_by_name`` +
        ``add`` (from the base repo) for the get-or-create flow.
        Keeping the "Local Dev" string in the API layer rather than
        here means the DB layer doesn't know about Phase-0 fallback
        conventions.
        """
        stmt = select(Project).where(Project.name == name)
        return session.execute(stmt).scalar_one_or_none()
