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
from sqlalchemy.orm import Session
from zynksec_db import FindingRepository, Scan, ScanRepository
from zynksec_schema import ScanProfile

from zynksec_api.celery_client import enqueue_scan
from zynksec_api.db import get_session
from zynksec_api.exceptions import ScanNotFound
from zynksec_api.routers._project_resolution import resolve_project_for_request
from zynksec_api.schemas import ScanCreate, ScanRead, TargetSummary, finding_from_row

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


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


def _scan_to_read(scan: Scan, findings: list[object]) -> ScanRead:
    """Explicit ORM -> Pydantic construction.

    Constructed field-by-field (rather than ``model_validate(scan)``)
    so the ``findings`` list is always well-typed — the ORM row has
    no ``findings`` attribute.

    The ``target`` field is built lazily from the loaded relationship
    when ``scan.target_id`` is set, ``None`` otherwise (legacy
    target_url scans + pre-Phase-2 rows).
    """
    target_summary: TargetSummary | None = None
    if scan.target_id is not None:
        target_row = scan.target  # SQLAlchemy lazy-load via FK
        if target_row is not None:
            target_summary = TargetSummary(
                id=target_row.id,
                name=target_row.name,
                url=target_row.url,
            )
    return ScanRead(
        id=scan.id,
        project_id=scan.project_id,
        target_url=scan.target_url,
        target=target_summary,
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
    """Persist a ``queued`` scan and dispatch the ``scan.run`` task.

    Every :class:`ScanProfile` value is implemented from Sprint 3 on;
    Pydantic rejects invalid wire values at the schema layer, so no
    runtime gate is needed here.
    """
    project = resolve_project_for_request(session, body.project_id)
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
