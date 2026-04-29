"""Scan endpoints — POST /api/v1/scans, GET /api/v1/scans/{id}.

Handlers use :class:`ScanRepository` and :class:`FindingRepository` via
FastAPI's ``Depends`` so they never touch raw sessions or queries
(CLAUDE.md §3).  Task arguments are stringified UUIDs — Celery payloads
are primitives only (CLAUDE.md §5).
"""

from __future__ import annotations

import uuid
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from zynksec_db import FindingRepository, Scan, ScanRepository, TargetRepository
from zynksec_schema import ScanProfile, zap_queue_for_index

from zynksec_api.celery_client import enqueue_scan_to_queue
from zynksec_api.config import get_settings
from zynksec_api.db import get_session
from zynksec_api.exceptions import ScanNotFound, ScanTargetSpecConflict, TargetNotFound
from zynksec_api.routers._project_resolution import resolve_project_for_request
from zynksec_api.schemas import ScanCreate, ScanRead, TargetSummary, finding_from_row

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency — returns a fresh :class:`ScanRepository`."""
    return ScanRepository()


def get_finding_repository() -> FindingRepository:
    """FastAPI dependency — returns a fresh :class:`FindingRepository`."""
    return FindingRepository()


def get_target_repository() -> TargetRepository:
    """FastAPI dependency — returns a fresh :class:`TargetRepository`."""
    return TargetRepository()


# Typed Depends aliases (FastAPI's modern Annotated style) — keeps
# Ruff B008 happy since defaults no longer contain a function call.
SessionDep = Annotated[Session, Depends(get_session)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]
FindingRepoDep = Annotated[FindingRepository, Depends(get_finding_repository)]
TargetRepoDep = Annotated[TargetRepository, Depends(get_target_repository)]


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
        scan_group_id=scan.scan_group_id,
        scan_profile=ScanProfile(scan.scan_profile),
        status=scan.status,  # type: ignore[arg-type]
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        failure_reason=scan.failure_reason,
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
    target_repo: TargetRepoDep,
) -> ScanRead:
    """Persist a ``queued`` scan and dispatch the ``scan.run`` task.

    Two input shapes (Phase 2 Sprint 1):

    1. ``target_id`` (recommended) — references a persistent
       :class:`zynksec_db.Target`.  URL + project come from the
       Target row; ``Scan.target_id`` is populated, the response's
       ``target`` field is the embedded summary.
    2. ``target_url`` (legacy) — direct URL, no Target row.  The
       handler creates the scan with ``target_id IS NULL``; the
       response ``target`` field is ``null``.  This path stays
       supported so existing callers don't break; new callers
       should migrate to the Target resource.

    Exactly one of the two must be provided.  Both / neither
    surface as a canonical-envelope ``scan_target_spec_conflict``
    422 (CLAUDE.md §4) — the XOR check is here at the router rather
    than as a Pydantic ``model_validator`` so the canonical envelope
    is what callers see.

    Every :class:`ScanProfile` value is implemented from Sprint 3 on;
    Pydantic rejects invalid wire values at the schema layer, so no
    runtime gate is needed here.
    """
    has_id = body.target_id is not None
    has_url = body.target_url is not None
    if has_id == has_url:  # both true or both false
        raise ScanTargetSpecConflict("exactly one of 'target_id' or 'target_url' must be provided")

    target_id_persisted: uuid.UUID | None = None
    if body.target_id is not None:
        target = target_repo.get(session, body.target_id)
        if target is None:
            raise TargetNotFound(f"target {body.target_id} does not exist")
        project_id = target.project_id
        target_url_value = target.url
        target_id_persisted = target.id
    else:
        # ``target_url`` legacy path.  ``body.target_url`` is HttpUrl
        # at this point (Pydantic validated); ``str()`` makes the
        # round-trip type-stable for the DB column.
        project = resolve_project_for_request(session, body.project_id)
        project_id = project.id
        target_url_value = str(body.target_url)

    # Phase 2 Sprint 3: pick the per-pair queue BEFORE the insert so
    # the row carries its ``assigned_queue`` from the very first
    # commit — no second UPDATE.  Rotation cursor is "row count
    # modulo N", computed inside the same transaction so two
    # concurrent POSTs see consistent neighbours and tend to
    # alternate (Postgres serializable isolation isn't required;
    # MVCC + the count's commit-ordering settle it correctly enough
    # for the legacy path's "approximately fair" guarantee).
    instance_index = _next_instance_index(session)
    queue = zap_queue_for_index(instance_index)

    scan = Scan(
        project_id=project_id,
        target_url=target_url_value,
        target_id=target_id_persisted,
        scan_profile=body.scan_profile.value,
        status="queued",
        assigned_queue=queue,
    )
    repo.add(session, scan)
    session.commit()

    # Celery args stay primitive (CLAUDE.md §5).  The queue we just
    # picked routes the task to the worker pinned to the matching
    # ZAP instance.
    enqueue_scan_to_queue(str(scan.id), body.scan_profile.value, queue=queue)
    # Freshly queued scans have no findings yet.
    return _scan_to_read(scan, findings=[])


def _next_instance_index(session: Session) -> int:
    """Pick the 1-based ZAP instance index for a legacy single-scan POST.

    Uses ``COUNT(*) FROM scans`` modulo ``ZAP_INSTANCE_COUNT`` as a
    restart-safe rotation cursor — no extra table, no Redis counter.
    The "+ 1" makes it 1-based to match ``zap_queue_for_index``.
    Race-tolerant: if two POSTs read the same count and pick the
    same queue, the worst case is one queue gets two scans in a
    row instead of perfectly alternating.  Acceptable for the
    legacy path; ScanGroups get strict round-robin in
    :mod:`zynksec_api.routers.scan_groups`.

    Caveat: changing ``ZAP_INSTANCE_COUNT`` between scans causes a
    brief skew (the modulo class shifts) — documented in
    ``docs/04_phase0_scaffolding.md``.  Bumping requires the matching
    compose edit anyway.
    """
    settings = get_settings()
    n = settings.zap_instance_count
    count = int(session.execute(sa.select(sa.func.count(Scan.id))).scalar_one() or 0)
    return (count % n) + 1


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
