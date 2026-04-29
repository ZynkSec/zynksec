"""API exception types returning the canonical error shape.

CLAUDE.md §4: every error response includes ``code``, ``message``,
``request_id``, and an optional ``details`` object.  A custom
exception handler registered in :mod:`zynksec_api.main` flattens the
Starlette ``{"detail": ...}`` wrapper so the body is exactly the four
documented keys.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import HTTPException, status


def _current_correlation_id() -> str | None:
    """Pull the correlation id bound by ``CorrelationIdMiddleware``.

    The error-response body still exposes it under the ``request_id``
    key per CLAUDE.md §4 (locked API contract) — only the log/header
    name is ``correlation_id``.  Same value, two labels.
    """
    bound = structlog.contextvars.get_contextvars()
    if isinstance(bound, dict):
        value = bound.get("correlation_id")
        return str(value) if value is not None else None
    return None


class ZynksecError(HTTPException):
    """Base class for Zynksec HTTP errors with the canonical body."""

    code: str = "zynksec_error"
    http_status: int = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        body: dict[str, Any] = {
            "code": self.code,
            "message": message,
            "request_id": _current_correlation_id(),
        }
        if details is not None:
            body["details"] = details
        super().__init__(status_code=self.http_status, detail=body)


class ScanNotFound(ZynksecError):  # noqa: N818 — HTTPException-style short name
    """404 — no scan row with the given id."""

    code = "scan_not_found"
    http_status = status.HTTP_404_NOT_FOUND


class ProjectNotFound(ZynksecError):  # noqa: N818 — HTTPException-style short name
    """404 — caller supplied a ``project_id`` that doesn't resolve.

    Phase 2 debt-paydown: previously the resolution helper silently
    fell back to the implicit Local Dev project when a non-existent
    id was provided.  That conflated "no project requested → defaults
    apply" (Phase 0 lenience) with "wrong project requested → caller
    is buggy or auth boundary leaks", and would have returned the
    wrong tenant's data under multi-tenancy.  We now surface the
    second case as an explicit 404 so the caller knows their request
    was rejected, not silently re-routed.
    """

    code = "project_not_found"
    http_status = status.HTTP_404_NOT_FOUND


class TargetNotFound(ZynksecError):  # noqa: N818 — HTTPException-style short name
    """404 — no target row with the given id."""

    code = "target_not_found"
    http_status = status.HTTP_404_NOT_FOUND


class TargetNameConflict(ZynksecError):  # noqa: N818 — HTTPException-style
    """409 — a Target with this ``name`` already exists in the project.

    The DB-level guarantee is the ``uq_targets_project_id_name``
    constraint; the API surfaces it as a polite 409 rather than
    letting an ``IntegrityError`` traceback escape.
    """

    code = "target_name_conflict"
    http_status = status.HTTP_409_CONFLICT


class TargetHasScans(ZynksecError):  # noqa: N818 — HTTPException-style
    """409 — DELETE /targets/{id} when scans still reference the target.

    The FK on ``scans.target_id`` is ``ON DELETE RESTRICT``; this is
    the polite pre-check before the DB constraint would fire, with a
    canonical envelope telling the operator how many scans are in the
    way.
    """

    code = "target_has_scans"
    http_status = status.HTTP_409_CONFLICT


class ScanTargetSpecConflict(ZynksecError):  # noqa: N818 — HTTPException-style
    """422 — POST /scans with both or neither of ``target_id``/``target_url``.

    The XOR check lives at the router (rather than as a Pydantic
    ``model_validator``) so callers get the canonical envelope
    instead of FastAPI's default ``{"detail": [...]}`` shape.
    Pydantic's per-field validation (``HttpUrl`` for ``target_url``,
    ``uuid.UUID`` for ``target_id``) still emits the standard 422
    shape — that's the known
    ``RequestValidationError`` gap, not changed in this sprint.
    """

    code = "scan_target_spec_conflict"
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY


class ScanGroupNotFound(ZynksecError):  # noqa: N818 — HTTPException-style
    """404 — no scan_group row with the given id."""

    code = "scan_group_not_found"
    http_status = status.HTTP_404_NOT_FOUND


class UnknownTargetIds(ZynksecError):  # noqa: N818 — HTTPException-style
    """422 — POST /scan-groups names target_id(s) that don't exist.

    All-or-nothing: the API rejects the whole request and rolls back
    rather than creating a partial group.  ``details.unknown_target_ids``
    lists the ids that didn't resolve so the caller can pinpoint
    them without diffing.
    """

    code = "unknown_target_ids"
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY


class DuplicateTargetIds(ZynksecError):  # noqa: N818 — HTTPException-style
    """422 — POST /scan-groups with the same target_id listed twice.

    The check lives at the router so the canonical envelope holds;
    Pydantic's container types don't enforce uniqueness on their
    own.  ``details.duplicate_target_ids`` lists each repeated id.
    """

    code = "duplicate_target_ids"
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY
