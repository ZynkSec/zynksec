"""Scan endpoints — POST /api/v1/scans, GET /api/v1/scans/{id}.

Handlers use :class:`ScanRepository` via FastAPI's ``Depends`` so they
never touch a raw session-or-query (CLAUDE.md §3).  Task arguments are
stringified UUIDs because Celery payloads are primitives only
(CLAUDE.md §5).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import Project, Scan, ScanRepository

from zynksec_api.celery_client import enqueue_scan
from zynksec_api.db import get_session
from zynksec_api.exceptions import ScanNotFound
from zynksec_api.schemas import ScanCreate, ScanRead

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

_IMPLICIT_PROJECT_NAME = "Local Dev"


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency — returns a fresh :class:`ScanRepository`."""
    return ScanRepository()


# Typed Depends aliases (FastAPI's modern Annotated style) — also keeps
# Ruff B008 happy since defaults no longer contain a function call.
SessionDep = Annotated[Session, Depends(get_session)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]


def _resolve_project(session: Session, project_id: uuid.UUID | None) -> Project:
    """Pick the project the new scan will belong to.

    If ``project_id`` is supplied, load it.  Otherwise (or if the given
    id has no matching row — Phase 0 is intentionally lenient here),
    fall back to the implicit "Local Dev" project (docs/04 §0.16).
    Phase 1 adds strict validation + 404 on unknown project ids.
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


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanRead,
    summary="Enqueue a new scan",
)
def create_scan(
    body: ScanCreate,
    session: SessionDep,
    repo: ScanRepoDep,
) -> ScanRead:
    """Persist a ``queued`` scan and dispatch the ``scan.run`` task."""
    project = _resolve_project(session, body.project_id)
    scan = Scan(
        project_id=project.id,
        target_url=str(body.target_url),
        status="queued",
    )
    repo.add(session, scan)
    session.commit()

    enqueue_scan(str(scan.id))
    return ScanRead.model_validate(scan)


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Read a scan by id",
)
def get_scan(
    scan_id: uuid.UUID,
    session: SessionDep,
    repo: ScanRepoDep,
) -> ScanRead:
    scan = repo.get(session, scan_id)
    if scan is None:
        raise ScanNotFound(f"scan {scan_id} does not exist")
    return ScanRead.model_validate(scan)
