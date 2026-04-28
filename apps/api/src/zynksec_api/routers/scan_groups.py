"""ScanGroup CRUD — POST + GET-one + GET-list on /api/v1/scan-groups.

Phase 2 Sprint 2: one API call enqueues a multi-target scan
request.  The handler:

    1. Validates that all ``target_ids`` exist and belong to the
       same project (resolved from the first Target's project, or
       from the request's optional ``project_id``).  Unknown or
       cross-project ids fail the whole request with a canonical
       envelope — no partial group.
    2. Persists the parent ScanGroup + N child Scan rows in a
       single transaction so the atomicity invariant holds: a
       caller that gets a 4xx never sees orphaned children.
    3. Enqueues one ``process_scan_group`` Celery task carrying
       just the group's id.  The worker picks it up, marks
       running, and iterates children serially (Sprint-2
       constraint: worker concurrency stays at 1).

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
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import (
    Scan,
    ScanGroup,
    ScanGroupRepository,
    ScanRepository,
    Target,
)
from zynksec_schema import ScanProfile

from zynksec_api.celery_client import enqueue_scan_group
from zynksec_api.db import get_session
from zynksec_api.exceptions import (
    DuplicateTargetIds,
    ScanGroupNotFound,
    UnknownTargetIds,
)
from zynksec_api.routers._project_resolution import resolve_project_for_request
from zynksec_api.schemas import ScanGroupCreate, ScanGroupRead, ScanGroupSummary

router = APIRouter(prefix="/api/v1/scan-groups", tags=["scan-groups"])


def get_scan_group_repository() -> ScanGroupRepository:
    """FastAPI dependency — returns a fresh :class:`ScanGroupRepository`."""
    return ScanGroupRepository()


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency — returns a fresh :class:`ScanRepository`."""
    return ScanRepository()


SessionDep = Annotated[Session, Depends(get_session)]
ScanGroupRepoDep = Annotated[ScanGroupRepository, Depends(get_scan_group_repository)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]


def _children_summary_and_ids(
    session: Session,
    scan_group_id: uuid.UUID,
) -> tuple[ScanGroupSummary, list[uuid.UUID]]:
    """Compute the per-status summary + ordered child id list.

    Reads all child Scan rows ordered by ``created_at`` so the id
    list matches the deterministic order the worker iterates in.
    Phase 2 Sprint 2 caps groups at 50 children, so a Python-side
    Counter is cheap; if N grows, this becomes a SQL aggregation.
    """
    stmt = (
        select(Scan.id, Scan.status)
        .where(Scan.scan_group_id == scan_group_id)
        .order_by(Scan.created_at.asc(), Scan.id.asc())
    )
    rows = list(session.execute(stmt).all())
    child_ids = [row[0] for row in rows]
    statuses: Counter[str] = Counter(row[1] for row in rows)
    summary = ScanGroupSummary(
        total=len(rows),
        queued=statuses.get("queued", 0),
        running=statuses.get("running", 0),
        completed=statuses.get("completed", 0),
        failed=statuses.get("failed", 0),
    )
    return summary, child_ids


def _scan_group_to_read(
    group: ScanGroup,
    summary: ScanGroupSummary,
    child_ids: list[uuid.UUID],
) -> ScanGroupRead:
    return ScanGroupRead(
        id=group.id,
        project_id=group.project_id,
        name=group.name,
        scan_profile=ScanProfile(group.scan_profile),
        status=group.status,  # type: ignore[arg-type]
        child_scan_ids=child_ids,
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
    session: Session,
    target_ids: list[uuid.UUID],
) -> list[Target]:
    """Fetch the requested Targets; raise canonical 422 if any are unknown.

    Returns the Targets in the SAME ORDER as ``target_ids`` so the
    child Scan rows the caller creates downstream end up in the
    same order as the request payload (the integration test reads
    on this ordering).
    """
    stmt = select(Target).where(Target.id.in_(target_ids))
    found = list(session.execute(stmt).scalars().all())
    found_by_id = {t.id: t for t in found}
    unknown = [tid for tid in target_ids if tid not in found_by_id]
    if unknown:
        raise UnknownTargetIds(
            f"{len(unknown)} target_id(s) do not exist",
            details={"unknown_target_ids": [str(tid) for tid in unknown]},
        )
    # Preserve request order — matters for child creation order.
    return [found_by_id[tid] for tid in target_ids]


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
    ``unknown_target_ids`` because, from the resolved project's
    point of view, those ids effectively don't exist.

    Targets are loaded inline via a single bulk
    ``SELECT ... WHERE id IN (...)`` query in :func:`_load_targets_or_422`
    rather than going through ``TargetRepository`` — pushing the bulk
    fetch into the repo is a separate follow-up.
    """
    _validate_target_ids(body.target_ids)
    project = resolve_project_for_request(session, body.project_id)

    targets = _load_targets_or_422(session, body.target_ids)
    cross_project = [t for t in targets if t.project_id != project.id]
    if cross_project:
        raise UnknownTargetIds(
            f"{len(cross_project)} target_id(s) belong to a different project",
            details={"unknown_target_ids": [str(t.id) for t in cross_project]},
        )

    group = ScanGroup(
        project_id=project.id,
        name=body.name,
        scan_profile=body.scan_profile.value,
        status="queued",
    )
    group_repo.add(session, group)

    # Children created in request order so the worker's
    # ``created_at, id`` ordering reproduces it.
    children: list[Scan] = []
    for target in targets:
        child = Scan(
            project_id=project.id,
            target_url=target.url,
            target_id=target.id,
            scan_group_id=group.id,
            scan_profile=body.scan_profile.value,
            status="queued",
        )
        scan_repo.add(session, child)
        children.append(child)

    session.commit()
    enqueue_scan_group(str(group.id))

    summary = ScanGroupSummary(
        total=len(children),
        queued=len(children),
        running=0,
        completed=0,
        failed=0,
    )
    return _scan_group_to_read(group, summary, [c.id for c in children])


@router.get(
    "",
    response_model=list[ScanGroupRead],
    summary="List ScanGroups in a project (newest first)",
)
def list_scan_groups(
    session: SessionDep,
    repo: ScanGroupRepoDep,
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
        summary, child_ids = _children_summary_and_ids(session, group.id)
        out.append(_scan_group_to_read(group, summary, child_ids))
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
) -> ScanGroupRead:
    group = repo.get(session, scan_group_id)
    if group is None:
        raise ScanGroupNotFound(f"scan_group {scan_group_id} does not exist")
    summary, child_ids = _children_summary_and_ids(session, group.id)
    return _scan_group_to_read(group, summary, child_ids)
