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
from zynksec_db import (
    CodeFindingRepository,
    FindingRepository,
    Scan,
    ScanRepository,
    TargetRepository,
)
from zynksec_scanners import (
    SCANNER_GITLEAKS,
    resolve_scanner,
    scanner_for_kind,
    scanners_for_kind,
)
from zynksec_scanners import (
    UnknownScanner as RegistryUnknownScanner,
)
from zynksec_schema import ScanProfile, code_queue, zap_queue_for_index

from zynksec_api.celery_client import enqueue_scan_to_queue
from zynksec_api.config import get_settings
from zynksec_api.db import get_session
from zynksec_api.exceptions import (
    ScanNotFound,
    ScanTargetSpecConflict,
    TargetNotFound,
    UnknownScanner,
)
from zynksec_api.routers._project_resolution import resolve_project_for_request
from zynksec_api.schemas import (
    CodeFindingRead,
    ScanCreate,
    ScanRead,
    TargetSummary,
    code_finding_from_row,
    finding_from_row,
)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency — returns a fresh :class:`ScanRepository`."""
    return ScanRepository()


def get_finding_repository() -> FindingRepository:
    """FastAPI dependency — returns a fresh :class:`FindingRepository`."""
    return FindingRepository()


def get_code_finding_repository() -> CodeFindingRepository:
    """FastAPI dependency — returns a fresh :class:`CodeFindingRepository`."""
    return CodeFindingRepository()


def get_target_repository() -> TargetRepository:
    """FastAPI dependency — returns a fresh :class:`TargetRepository`."""
    return TargetRepository()


# Typed Depends aliases (FastAPI's modern Annotated style) — keeps
# Ruff B008 happy since defaults no longer contain a function call.
SessionDep = Annotated[Session, Depends(get_session)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]
FindingRepoDep = Annotated[FindingRepository, Depends(get_finding_repository)]
CodeFindingRepoDep = Annotated[CodeFindingRepository, Depends(get_code_finding_repository)]
TargetRepoDep = Annotated[TargetRepository, Depends(get_target_repository)]


def _scan_to_read(
    scan: Scan,
    findings: list[object],
    code_findings: list[CodeFindingRead] | None = None,
) -> ScanRead:
    """Explicit ORM -> Pydantic construction.

    Constructed field-by-field (rather than ``model_validate(scan)``)
    so the ``findings`` / ``code_findings`` lists are always
    well-typed — the ORM row has no such attribute.

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
        scanner=scan.scanner,
        findings=findings,  # type: ignore[arg-type]
        code_findings=code_findings or [],
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
    target_kind: str = "web_app"  # legacy ``target_url``-only POSTs
    if body.target_id is not None:
        target = target_repo.get(session, body.target_id)
        if target is None:
            raise TargetNotFound(f"target {body.target_id} does not exist")
        project_id = target.project_id
        target_url_value = target.url
        target_id_persisted = target.id
        target_kind = target.kind
    else:
        # ``target_url`` legacy path.  ``body.target_url`` is HttpUrl
        # at this point (Pydantic validated); ``str()`` makes the
        # round-trip type-stable for the DB column.
        project = resolve_project_for_request(session, body.project_id)
        project_id = project.id
        target_url_value = str(body.target_url)

    # Phase 3 Sprint 2: resolve the scanner name.  ``body.scanner``
    # is None for the default-pick path; an explicit value is
    # validated against the registry.  Mismatch surfaces as a
    # canonical-envelope 422 ``unknown_scanner`` with
    # ``details.available`` listing the valid scanners for this
    # kind so callers can pick a working name.
    try:
        resolved_scanner = resolve_scanner(target_kind, body.scanner)  # type: ignore[arg-type]
    except RegistryUnknownScanner as exc:
        raise UnknownScanner(
            f"scanner {body.scanner!r} is not available for kind {target_kind!r}",
            details={
                "requested": body.scanner,
                "kind": target_kind,
                "available": sorted(scanners_for_kind(target_kind)),  # type: ignore[arg-type]
            },
        ) from exc

    # Phase 3 Sprint 1: scanner family routing.  ``repo`` Targets
    # land on ``code_q`` (gitleaks / semgrep); everything else
    # stays on the per-pair ZAP queues.  The legacy ``target_url``
    # POST has no Target row so kind defaults to ``web_app`` and
    # routes to ZAP — preserving existing client behaviour.
    queue = _queue_for_kind(target_kind, session, repo)

    scan = Scan(
        project_id=project_id,
        target_url=target_url_value,
        target_id=target_id_persisted,
        scan_profile=body.scan_profile.value,
        status="queued",
        assigned_queue=queue,
        # Persist the RESOLVED name (not the user input).  Sprint 1
        # cleanup item #10 contract: API write-time and worker
        # run-time agree on the scanner identity.
        scanner=resolved_scanner,
    )
    repo.add(session, scan)
    session.commit()

    # Celery args stay primitive (CLAUDE.md §5).  The queue we just
    # picked routes the task to the worker pinned to the matching
    # ZAP instance.
    enqueue_scan_to_queue(str(scan.id), body.scan_profile.value, queue=queue)
    # Freshly queued scans have no findings yet.
    return _scan_to_read(scan, findings=[])


def _queue_for_kind(
    target_kind: str,
    session: Session,
    repo: ScanRepository,
) -> str:
    """Map ``Target.kind`` to the Celery queue this scan dispatches on.

    Phase 3 Sprint 1: ``repo`` -> ``code_q`` (gitleaks code-worker
    family); ``web_app`` / ``api`` -> per-pair ZAP queue picked by
    the rotation cursor below.  The registry in
    :mod:`zynksec_scanners.registry` is the source of truth for the
    family mapping; we read it here so a future scanner-family
    addition (e.g. trivy on its own queue) is one registry edit
    plus a queue helper, no router edits.
    """
    family = scanner_for_kind(target_kind)  # type: ignore[arg-type]
    if family == SCANNER_GITLEAKS:
        return code_queue()
    # ZAP family: rotation-cursor across the per-pair queues.
    instance_index = _next_instance_index(session, repo)
    return zap_queue_for_index(instance_index)


def _next_instance_index(session: Session, repo: ScanRepository) -> int:
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
    count = repo.total_count(session)
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
    code_finding_repo: CodeFindingRepoDep,
) -> ScanRead:
    scan = repo.get(session, scan_id)
    if scan is None:
        raise ScanNotFound(f"scan {scan_id} does not exist")

    # Phase 3 Sprint 1: which finding family this scan produced
    # depends on the Target's kind.  Repo-scanner scans live in
    # ``code_findings``; ZAP scans in ``findings``.  Reading both
    # blindly would double the query load on every GET; instead we
    # branch.  Legacy ``target_url`` scans (no Target row) default
    # to ZAP / ``findings``.
    target_kind = scan.target.kind if scan.target is not None else "web_app"
    if scanner_for_kind(target_kind) == SCANNER_GITLEAKS:  # type: ignore[arg-type]
        code_finding_rows = code_finding_repo.list_by_scan(session, scan_id)
        return _scan_to_read(
            scan,
            findings=[],
            code_findings=[code_finding_from_row(row) for row in code_finding_rows],
        )

    finding_rows = finding_repo.list(session, scan_id=scan_id)
    findings = [finding_from_row(row) for row in finding_rows]
    return _scan_to_read(scan, findings)
