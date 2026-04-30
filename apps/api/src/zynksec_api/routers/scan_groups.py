"""ScanGroup CRUD — POST + GET-one + GET-list on /api/v1/scan-groups.

Phase 2 Sprint 2 / Sprint 3: one API call enqueues a multi-target
scan request.  The handler:

    1. Validates that all ``target_ids`` exist and belong to the
       same project (resolved from the first Target's project, or
       from the request's optional ``project_id``).  Unknown or
       cross-project ids fail the whole request with a canonical
       envelope — no partial group.
    2. Persists the parent ScanGroup + N child Scan rows in a
       single transaction so the atomicity invariant holds: a
       caller that gets a 4xx never sees orphaned children.  Each
       child is assigned a per-pair Celery queue (``zap_q_1`` /
       ``zap_q_2`` / ...) round-robin so children of the same group
       fan out across ZAP instances.
    3. Enqueues one ``scan.run`` Celery task per child, each
       routed to its assigned queue.  Sprint 3 collapsed the
       umbrella ``scan_group.process`` task — children execute in
       parallel on whichever worker pair owns their queue, and
       roll up the parent group atomically when the last child
       terminates (last-child-wins, no coordinator).

Reading a group: ``GET /api/v1/scan-groups/{id}`` returns the row
plus a summary computed on-the-fly from the child Scans, so the
counts never drift from the underlying source of truth.

CLAUDE.md §3 (repository pattern) — no raw SQL outside repos.
CLAUDE.md §4 (canonical envelope) — every 4xx surfaces as a
``ZynksecError`` subclass.
CLAUDE.md §5 (Celery primitives) — task args are stringified UUIDs.
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from zynksec_db import (
    Scan,
    ScanGroup,
    ScanGroupRepository,
    ScanRepository,
    Target,
    TargetRepository,
)
from zynksec_scanners import SCANNER_GITLEAKS, scanner_for_kind
from zynksec_schema import ScanProfile, code_queue, zap_queue_for_index

from zynksec_api.celery_client import enqueue_scan_to_queue
from zynksec_api.config import get_settings
from zynksec_api.db import get_session
from zynksec_api.exceptions import (
    DuplicateTargetIds,
    ScanGroupNotFound,
    UnknownTargetIds,
)
from zynksec_api.routers._project_resolution import resolve_project_for_request
from zynksec_api.schemas import ScanGroupCreate, ScanGroupRead, ScanGroupSummary, ScanRead
from zynksec_api.schemas.target import TargetSummary

router = APIRouter(prefix="/api/v1/scan-groups", tags=["scan-groups"])


def get_scan_group_repository() -> ScanGroupRepository:
    """FastAPI dependency — returns a fresh :class:`ScanGroupRepository`."""
    return ScanGroupRepository()


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency — returns a fresh :class:`ScanRepository`."""
    return ScanRepository()


def get_target_repository() -> TargetRepository:
    """FastAPI dependency — returns a fresh :class:`TargetRepository`."""
    return TargetRepository()


SessionDep = Annotated[Session, Depends(get_session)]
ScanGroupRepoDep = Annotated[ScanGroupRepository, Depends(get_scan_group_repository)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]
TargetRepoDep = Annotated[TargetRepository, Depends(get_target_repository)]


def _child_scan_to_read(scan: Scan) -> ScanRead:
    """Build a :class:`ScanRead` for a child embedded in a group response.

    ``findings`` is intentionally empty — the group response surfaces
    every child's status / failure_reason / queue assignment without
    expanding findings (clients ``GET /api/v1/scans/{id}`` to drill
    in).  The Target relationship has ``lazy="joined"`` on the model
    so reading ``scan.target`` doesn't introduce N+1.
    """
    target_summary: TargetSummary | None = None
    if scan.target_id is not None and scan.target is not None:
        target_summary = TargetSummary(
            id=scan.target.id,
            name=scan.target.name,
            url=scan.target.url,
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
        findings=[],
    )


def _children_rollup(
    scan_repo: ScanRepository,
    session: Session,
    scan_group_id: uuid.UUID,
) -> tuple[ScanGroupSummary, list[uuid.UUID], list[ScanRead]]:
    """Per-status summary + ordered child id list + embedded ScanReads.

    Reads via :meth:`ScanRepository.list_by_group` (deterministic
    ``(created_at, id)`` ordering) so the id list matches the order
    the worker iterates in.  Phase 2 Sprint 2 caps groups at 50
    children, so building N ScanRead objects in-process is cheap;
    if N grows, the embedded list becomes a paginated sub-resource.
    """
    children = scan_repo.list_by_group(session, scan_group_id)
    child_ids = [c.id for c in children]
    child_scans = [_child_scan_to_read(c) for c in children]
    statuses: Counter[str] = Counter(c.status for c in children)
    summary = ScanGroupSummary(
        total=len(children),
        queued=statuses.get("queued", 0),
        running=statuses.get("running", 0),
        completed=statuses.get("completed", 0),
        failed=statuses.get("failed", 0),
    )
    return summary, child_ids, child_scans


def _scan_group_to_read(
    group: ScanGroup,
    summary: ScanGroupSummary,
    child_ids: list[uuid.UUID],
    child_scans: list[ScanRead],
) -> ScanGroupRead:
    return ScanGroupRead(
        id=group.id,
        project_id=group.project_id,
        name=group.name,
        scan_profile=ScanProfile(group.scan_profile),
        status=group.status,  # type: ignore[arg-type]
        child_scan_ids=child_ids,
        child_scans=child_scans,
        summary=summary,
        started_at=group.started_at,
        completed_at=group.completed_at,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


def _validate_target_ids(target_ids: list[uuid.UUID]) -> None:
    """Reject duplicates with a canonical envelope.

    Pydantic enforces min/max length on the list itself; uniqueness
    is the API layer's responsibility because canonical envelope
    consistency requires the check live at the router.
    """
    counts = Counter(target_ids)
    duplicates = sorted({tid for tid, count in counts.items() if count > 1})
    if duplicates:
        raise DuplicateTargetIds(
            f"target_ids list contains {len(duplicates)} duplicate id(s)",
            details={"duplicate_target_ids": [str(tid) for tid in duplicates]},
        )


def _load_targets_or_422(
    target_repo: TargetRepository,
    session: Session,
    target_ids: list[uuid.UUID],
    *,
    project_id: uuid.UUID,
) -> list[Target]:
    """Fetch the requested Targets; raise canonical 422 if any are unknown.

    Goes through :meth:`TargetRepository.bulk_get`, which filters the
    ``IN (...)`` query by ``project_id`` so cross-project ids are
    treated identically to truly-missing ids — a client can't
    distinguish "doesn't exist anywhere" from "exists in a different
    project" by string-matching the response body, which would leak
    existence under multi-tenant auth (Phase 1+).

    Returns Targets in the SAME ORDER as ``target_ids`` so the
    child Scan rows the caller creates downstream end up in the
    same order as the request payload.
    """
    found = target_repo.bulk_get(session, target_ids, project_id=project_id)
    found_ids = {t.id for t in found}
    unknown = [tid for tid in target_ids if tid not in found_ids]
    if unknown:
        raise UnknownTargetIds(
            "one or more target_ids do not exist in this project",
            details={"unknown_target_ids": [str(tid) for tid in unknown]},
        )
    return found


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanGroupRead,
    summary="Enqueue a multi-target scan",
)
def create_scan_group(
    body: ScanGroupCreate,
    session: SessionDep,
    group_repo: ScanGroupRepoDep,
    scan_repo: ScanRepoDep,
    target_repo: TargetRepoDep,
) -> ScanGroupRead:
    """Persist parent ScanGroup + N child Scan rows + enqueue worker.

    Atomicity: all DB writes are committed together.  If any
    target_id is unknown, we raise before any insert — the request
    rolls back at the session level and the caller never sees a
    partially-created group.

    Project resolution: the new group belongs to the project the
    request specifies (or the implicit Local Dev project if
    omitted).  All Target rows must belong to the SAME project as
    the resolved group; cross-project membership is rejected as
    ``unknown_target_ids`` (same envelope as truly-missing) so
    existence doesn't leak across project boundaries.

    Targets are loaded via :meth:`TargetRepository.bulk_get`, which
    filters by ``project_id`` at the DB level — the router doesn't
    need a separate cross-project check.
    """
    _validate_target_ids(body.target_ids)
    project = resolve_project_for_request(session, body.project_id)

    targets = _load_targets_or_422(target_repo, session, body.target_ids, project_id=project.id)

    group = ScanGroup(
        project_id=project.id,
        name=body.name,
        scan_profile=body.scan_profile.value,
        status="queued",
    )
    group_repo.add(session, group)

    # Phase 2 Sprint 3: round-robin ZAP children across the per-pair
    # queues.  Phase 3 Sprint 1: ``repo`` children skip the rotation
    # entirely and land on ``code_q``.  Mixed groups (e.g. one web_app
    # + one repo) distribute correctly: ZAP children round-robin
    # against each other, repo children all share ``code_q``.  We
    # increment a separate ``zap_idx`` cursor that ONLY advances on
    # ZAP children so a leading repo child doesn't shift the ZAP
    # rotation by one.
    #
    # Persisting ``assigned_queue`` on the child Scan row inside
    # the same transaction means the queue selection is committed
    # atomically with the child itself — no risk of an enqueue
    # without a record, or a record without an enqueue.
    n_instances = get_settings().zap_instance_count

    # Children created in request order so the worker's
    # ``created_at, id`` ordering reproduces it.
    children: list[Scan] = []
    child_queues: list[str] = []
    zap_idx = 0
    for target in targets:
        family = scanner_for_kind(target.kind)  # type: ignore[arg-type]
        if family == SCANNER_GITLEAKS:
            queue = code_queue()
        else:
            queue = zap_queue_for_index((zap_idx % n_instances) + 1)
            zap_idx += 1
        child = Scan(
            project_id=project.id,
            target_url=target.url,
            target_id=target.id,
            scan_group_id=group.id,
            scan_profile=body.scan_profile.value,
            status="queued",
            assigned_queue=queue,
        )
        scan_repo.add(session, child)
        children.append(child)
        child_queues.append(queue)

    session.commit()

    # Enqueue AFTER the commit so a worker that picks the task up
    # mid-flight always finds a fully-persisted Scan row.  One task
    # per child — the worker's ``execute_scan`` rolls up the parent
    # group atomically when the last child terminates (Sprint 3:
    # ``mark_terminal_if_all_children_done``).
    for child, queue in zip(children, child_queues, strict=True):
        enqueue_scan_to_queue(str(child.id), body.scan_profile.value, queue=queue)

    summary = ScanGroupSummary(
        total=len(children),
        queued=len(children),
        running=0,
        completed=0,
        failed=0,
    )
    child_scans = [_child_scan_to_read(c) for c in children]
    return _scan_group_to_read(group, summary, [c.id for c in children], child_scans)


@router.get(
    "",
    response_model=list[ScanGroupRead],
    summary="List ScanGroups in a project (newest first)",
)
def list_scan_groups(
    session: SessionDep,
    repo: ScanGroupRepoDep,
    scan_repo: ScanRepoDep,
    project_id: Annotated[uuid.UUID | None, Query()] = None,
) -> list[ScanGroupRead]:
    """List groups in a project, newest first.

    No pagination this sprint — Phase 2 Sprint 1 deferred the same
    decision for ``GET /api/v1/targets``; both endpoints get
    pagination together in a focused follow-up.
    """
    project = resolve_project_for_request(session, project_id)
    groups = repo.list_by_project(session, project.id)
    out: list[ScanGroupRead] = []
    for group in groups:
        summary, child_ids, child_scans = _children_rollup(scan_repo, session, group.id)
        out.append(_scan_group_to_read(group, summary, child_ids, child_scans))
    return out


@router.get(
    "/{scan_group_id}",
    response_model=ScanGroupRead,
    summary="Read a ScanGroup by id (with rolled-up summary)",
)
def get_scan_group(
    scan_group_id: uuid.UUID,
    session: SessionDep,
    repo: ScanGroupRepoDep,
    scan_repo: ScanRepoDep,
) -> ScanGroupRead:
    group = repo.get(session, scan_group_id)
    if group is None:
        raise ScanGroupNotFound(f"scan_group {scan_group_id} does not exist")
    summary, child_ids, child_scans = _children_rollup(scan_repo, session, group.id)
    return _scan_group_to_read(group, summary, child_ids, child_scans)
