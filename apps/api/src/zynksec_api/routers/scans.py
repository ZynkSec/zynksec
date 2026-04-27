"""Scan endpoints — POST /api/v1/scans, GET /api/v1/scans/{id}.

Handlers use :class:`ScanRepository` and :class:`FindingRepository` via
FastAPI's ``Depends`` so they never touch raw sessions or queries
(CLAUDE.md §3).  Task arguments are stringified UUIDs — Celery payloads
are primitives only (CLAUDE.md §5).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import FindingRepository, Project, Scan, ScanRepository
from zynksec_schema import ScanProfile

from zynksec_api.celery_client import enqueue_scan
from zynksec_api.db import get_session
from zynksec_api.exceptions import ScanNotFound, ScanProfileNotImplemented
from zynksec_api.schemas import ScanCreate, ScanRead, finding_from_row

# Phase 1 Sprint 1 ships ``PASSIVE`` only.  Other profiles are valid in
# the OpenAPI spec but rejected at runtime so users see a clear error
# instead of a Celery task failure.
_IMPLEMENTED_SCAN_PROFILES: frozenset[ScanProfile] = frozenset({ScanProfile.PASSIVE})

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

_IMPLICIT_PROJECT_NAME = "Local Dev"


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency — returns a fresh :class:`ScanRepository`."""
    return ScanRepository()


def get_finding_repository() -> FindingRepository:
    """FastAPI dependency — returns a fresh :class:`FindingRepository`."""
    return FindingRepository()


# Typed Depends aliases (FastAPI's modern Annotated style) — keeps
# Ruff B008 happy since defaults no longer contain a function call.
SessionDep = Annotated[Session, Depends(get_session)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]
FindingRepoDep = Annotated[FindingRepository, Depends(get_finding_repository)]


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


def _scan_to_read(scan: Scan, findings: list[object]) -> ScanRead:
    """Explicit ORM -> Pydantic construction.

    Constructed field-by-field (rather than ``model_validate(scan)``)
    so the ``findings`` list is always well-typed — the ORM row has
    no ``findings`` attribute.
    """
    return ScanRead(
        id=scan.id,
        project_id=scan.project_id,
        target_url=scan.target_url,
        scan_profile=ScanProfile(scan.scan_profile),
        status=scan.status,  # type: ignore[arg-type]
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        findings=findings,  # type: ignore[arg-type]
    )


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
    if body.scan_profile not in _IMPLEMENTED_SCAN_PROFILES:
        raise ScanProfileNotImplemented(
            f"scan_profile {body.scan_profile.value!r} is accepted by the schema but "
            "not yet implemented. Tracking in Phase 1 Sprint 2. Use 'PASSIVE' for now."
        )

    project = _resolve_project(session, body.project_id)
    scan = Scan(
        project_id=project.id,
        target_url=str(body.target_url),
        scan_profile=body.scan_profile.value,
        status="queued",
    )
    repo.add(session, scan)
    session.commit()

    enqueue_scan(str(scan.id), body.scan_profile.value)
    # Freshly queued scans have no findings yet.
    return _scan_to_read(scan, findings=[])


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Read a scan by id (with its findings)",
)
def get_scan(
    scan_id: uuid.UUID,
    session: SessionDep,
    repo: ScanRepoDep,
    finding_repo: FindingRepoDep,
) -> ScanRead:
    scan = repo.get(session, scan_id)
    if scan is None:
        raise ScanNotFound(f"scan {scan_id} does not exist")

    finding_rows = finding_repo.list(session, scan_id=scan_id)
    findings = [finding_from_row(row) for row in finding_rows]
    return _scan_to_read(scan, findings)
