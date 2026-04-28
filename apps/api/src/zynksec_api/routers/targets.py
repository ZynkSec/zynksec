"""Target CRUD — POST/GET-list/GET-one/DELETE on /api/v1/targets.

Phase 2 Sprint 1: introduces the persistent Target resource that
scans reference.  Handlers go through :class:`TargetRepository` (no
raw SQL — CLAUDE.md §3) and surface uniqueness + scan-reference
violations as canonical-envelope errors (CLAUDE.md §4).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from zynksec_db import Project, Target, TargetRepository

from zynksec_api.db import get_session
from zynksec_api.exceptions import TargetHasScans, TargetNameConflict, TargetNotFound
from zynksec_api.routers._project_resolution import resolve_project_for_request
from zynksec_api.schemas import TargetCreate, TargetRead

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])


def get_target_repository() -> TargetRepository:
    """FastAPI dependency — returns a fresh :class:`TargetRepository`."""
    return TargetRepository()


SessionDep = Annotated[Session, Depends(get_session)]
TargetRepoDep = Annotated[TargetRepository, Depends(get_target_repository)]


def _target_to_read(target: Target) -> TargetRead:
    return TargetRead(
        id=target.id,
        project_id=target.project_id,
        name=target.name,
        url=target.url,
        kind=target.kind,  # type: ignore[arg-type]
        created_at=target.created_at,
        updated_at=target.updated_at,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=TargetRead,
    summary="Create a Target",
)
def create_target(
    body: TargetCreate,
    session: SessionDep,
    repo: TargetRepoDep,
) -> TargetRead:
    """Persist a new Target.

    Project resolution mirrors the scan-create pattern: when
    ``project_id`` is omitted, the implicit "Local Dev" project is
    auto-created on first use.  Uniqueness on ``(project_id, name)``
    is enforced at the DB layer; we catch the resulting
    ``IntegrityError`` and translate it to a canonical 409 so callers
    see ``target_name_conflict`` instead of a server-side traceback.
    """
    project: Project = resolve_project_for_request(session, body.project_id)
    target = Target(
        project_id=project.id,
        name=body.name,
        url=str(body.url),
        kind=body.kind,
    )
    try:
        repo.add(session, target)
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise TargetNameConflict(
            f"a Target named {body.name!r} already exists in this project"
        ) from exc
    return _target_to_read(target)


@router.get(
    "",
    response_model=list[TargetRead],
    summary="List Targets in a project",
)
def list_targets(
    session: SessionDep,
    repo: TargetRepoDep,
    project_id: Annotated[uuid.UUID | None, Query()] = None,
) -> list[TargetRead]:
    """List Targets in a project.

    ``project_id`` is optional; when omitted, the implicit Local Dev
    project is used (same convention as scan + target creation).
    """
    project = resolve_project_for_request(session, project_id)
    rows = repo.list_by_project(session, project.id)
    return [_target_to_read(t) for t in rows]


@router.get(
    "/{target_id}",
    response_model=TargetRead,
    summary="Read a Target by id",
)
def get_target(
    target_id: uuid.UUID,
    session: SessionDep,
    repo: TargetRepoDep,
) -> TargetRead:
    target = repo.get(session, target_id)
    if target is None:
        raise TargetNotFound(f"target {target_id} does not exist")
    return _target_to_read(target)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a Target",
)
def delete_target(
    target_id: uuid.UUID,
    session: SessionDep,
    repo: TargetRepoDep,
) -> None:
    """Delete a Target.

    Returns 404 if it doesn't exist.  Returns 409 ``target_has_scans``
    if any Scan still references the Target — the FK is
    ``ON DELETE RESTRICT`` so we'd hit an ``IntegrityError`` either
    way; the polite pre-check via ``scan_count`` lets the canonical
    envelope name the actual count, which is far more useful than a
    bare DB error.
    """
    target = repo.get(session, target_id)
    if target is None:
        raise TargetNotFound(f"target {target_id} does not exist")

    scan_count = repo.scan_count(session, target_id)
    if scan_count > 0:
        raise TargetHasScans(
            f"cannot delete target {target_id}: {scan_count} scan(s) reference it",
            details={"scan_count": scan_count},
        )

    repo.delete(session, target_id)
    session.commit()
