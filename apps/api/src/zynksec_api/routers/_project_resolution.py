"""Shared project-resolution helper for routers.

Phase 0 introduced the implicit "Local Dev" project so the walking-
skeleton scan flow could work without a project-create endpoint
(docs/04 §0.16).  Phase 2 Sprint 1's targets router needs the same
auto-create-default behaviour, and CLAUDE.md §3 (DRY) says shared
across-router logic lives once, not twice.

Phase 1+ tightens project resolution (404 on unknown project_id,
explicit project membership checks for active scans).  Until then,
this helper is intentionally lenient: an unknown ``project_id``
silently falls back to Local Dev rather than 404'ing.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import Project

_IMPLICIT_PROJECT_NAME = "Local Dev"


def resolve_project_for_request(
    session: Session,
    project_id: uuid.UUID | None,
) -> Project:
    """Pick the project a new resource (scan / target) will belong to.

    If ``project_id`` is supplied, load it.  Otherwise (or if the
    given id has no matching row — Phase 0 is intentionally lenient
    here), fall back to the implicit Local Dev project, creating it
    if needed.  Phase 1+ will replace the silent fallback with a
    proper 404.
    """
    if project_id is not None:
        found = session.get(Project, project_id)
        if found is not None:
            return found
    return _get_or_create_local_dev(session)


def _get_or_create_local_dev(session: Session) -> Project:
    stmt = select(Project).where(Project.name == _IMPLICIT_PROJECT_NAME)
    project = session.execute(stmt).scalar_one_or_none()
    if project is None:
        project = Project(name=_IMPLICIT_PROJECT_NAME)
        session.add(project)
        session.flush()
    return project
