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
