"""Shared project-resolution helper for routers.

Phase 0 introduced the implicit "Local Dev" project so the walking-
skeleton scan flow could work without a project-create endpoint
(docs/04 §0.16).  Phase 2 Sprint 1's targets router needs the same
auto-create-default behaviour, and CLAUDE.md §3 (DRY) says shared
across-router logic lives once, not twice.

Phase 2 debt-paydown: distinguishes two cases that used to collapse
into the same Local-Dev fallback —

    project_id OMITTED       → implicit Local Dev (Phase 0 lenience)
    project_id PROVIDED but
        not in the DB        → canonical 404 ``project_not_found``

The former is acceptable while there's no project-create endpoint;
the latter is a bug or auth-boundary leak we don't want to mask
once Phase 1+ multi-tenancy lands.  Surfacing it as a 404 also tells
the caller their request was rejected rather than silently routed
to a different tenant's data.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import Project

from zynksec_api.exceptions import ProjectNotFound

_IMPLICIT_PROJECT_NAME = "Local Dev"


def resolve_project_for_request(
    session: Session,
    project_id: uuid.UUID | None,
) -> Project:
    """Pick the project a new resource (scan / target) will belong to.

    If ``project_id`` is omitted, return (creating if necessary) the
    implicit Local Dev project — Phase 0 lenience for the walking-
    skeleton flow.  If ``project_id`` is supplied but doesn't resolve,
    raise :class:`ProjectNotFound` (canonical 404 envelope) rather
    than silently falling back; see this module's docstring for why
    that distinction matters.
    """
    if project_id is None:
        return _get_or_create_local_dev(session)
    found = session.get(Project, project_id)
    if found is None:
        raise ProjectNotFound(f"project {project_id} does not exist")
    return found


def _get_or_create_local_dev(session: Session) -> Project:
    stmt = select(Project).where(Project.name == _IMPLICIT_PROJECT_NAME)
    project = session.execute(stmt).scalar_one_or_none()
    if project is None:
        project = Project(name=_IMPLICIT_PROJECT_NAME)
        session.add(project)
        session.flush()
    return project
