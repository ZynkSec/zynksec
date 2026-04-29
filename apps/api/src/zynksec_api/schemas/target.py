"""Target request and response models — Phase 2 Sprint 1.

Co-located with the existing scan schemas (CLAUDE.md §3).  ``url`` is
validated via ``HttpUrl`` so the same Pydantic rules the existing
``ScanCreate.target_url`` field used apply here unchanged — no new
URL-validation surface for ``web_app`` / ``api`` kinds.

Phase 3 Sprint 1: when ``kind="repo"`` the URL must additionally
satisfy the cloner's allow-list (https-only, github / gitlab /
bitbucket hosts by default, no userinfo).  The model_validator
delegates to :func:`zynksec_scanners.repo.validate_clone_url` so
the API and the cloner share one source of truth — a Target that
survives ``POST /targets`` validation is one the cloner will
accept at scan-time.  Hard-denied schemes (``ssh``, ``git``,
``file``) are already filtered by ``HttpUrl`` itself; the
model_validator catches the remaining cases (host not on the
allow-list, embedded userinfo, length > 2048).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, HttpUrl, model_validator
from zynksec_scanners.repo import CloneError, validate_clone_url

# Mirrors :data:`zynksec_scanners.types.TargetKind`; keeping the
# Literal here (rather than importing from scanners) avoids dragging
# the scanners package into the API request-body type graph.
TargetKindLiteral = Literal["web_app", "api", "repo"]


class TargetCreate(BaseModel):
    """Body of ``POST /api/v1/targets``.

    ``project_id`` is optional — when omitted the handler falls back
    to the implicit "Local Dev" project (same auto-create pattern
    that scans use).  ``kind`` defaults to ``"web_app"``; the only
    other accepted values are ``"api"`` and ``"repo"``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    url: HttpUrl
    project_id: uuid.UUID | None = None
    kind: TargetKindLiteral = "web_app"

    @model_validator(mode="after")
    def _validate_kind_specific_url(self) -> TargetCreate:
        """Apply per-kind URL constraints.

        Only ``kind="repo"`` adds extra constraints today.  Failures
        bubble up as :class:`pydantic.ValidationError`, which the
        canonical-envelope handler in :mod:`zynksec_api.main` flattens
        into the standard ``{code, message, request_id, details}``
        shape (CLAUDE.md §4).
        """
        if self.kind == "repo":
            try:
                validate_clone_url(str(self.url))
            except CloneError as exc:
                raise ValueError(f"invalid repo URL: {exc}") from exc
        return self


class TargetRead(BaseModel):
    """Response body for the full Target record (POST/GET-one)."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    url: str
    kind: TargetKindLiteral
    created_at: datetime
    updated_at: datetime


class TargetSummary(BaseModel):
    """Compact form embedded in scan responses — ``id``, ``name``, ``url``.

    Scans don't need to surface every Target column on every read;
    the summary keeps ``GET /api/v1/scans/{id}`` payloads compact and
    the wire contract honest about what the scan-handler actually
    needs to know.
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    name: str
    url: str
