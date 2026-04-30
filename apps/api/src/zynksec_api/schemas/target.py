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

Phase 3 Sprint 1 pre-merge security review FINDING #6: the
userinfo rejection now applies to ALL kinds, not just ``repo``.
Pydantic's ``HttpUrl`` accepts ``https://user:pass@example.com/``;
without an explicit reject, those credentials get persisted on
``Target.url`` and surface in:
  * ``_log.error("scan.run.unsupported_target", ..., url=target.url)``
  * GET /api/v1/scans/{id} response (embedded ``target.url``)
  * structlog scope on every URL-tagged log line

Userinfo in URLs is universally a bad pattern — credentials
belong in headers / a token store, not URL strings.  Reject
across the board.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

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
        """Apply universal + per-kind URL constraints.

        Universal: reject embedded userinfo (``https://user:pass@host/``)
        for ALL kinds.  Pydantic's ``HttpUrl`` accepts userinfo by
        default; without an explicit reject the credentials would
        persist on ``Target.url`` and surface in logs, the GET
        response, and structlog scope.  Universal because it's never
        a good idea regardless of scanner family.

        Per-kind: ``kind="repo"`` additionally goes through
        :func:`zynksec_scanners.repo.validate_clone_url` (host
        allow-list, scheme allow-list, control-char rejection,
        path-traversal rejection, IP-literal SSRF rejection — see
        the cloner module for the full set).

        Failures bubble up as :class:`pydantic.ValidationError`,
        which the canonical-envelope handler in
        :mod:`zynksec_api.main` flattens into the standard
        ``{code, message, request_id, details}`` shape (CLAUDE.md §4).
        """
        # Universal: no userinfo in URLs (FINDING #6).
        parts = urlsplit(str(self.url))
        if parts.username is not None or parts.password is not None:
            raise ValueError(
                "URL must not include userinfo (username / password); "
                "credentials belong in a token store or auth header, not URL strings",
            )

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
