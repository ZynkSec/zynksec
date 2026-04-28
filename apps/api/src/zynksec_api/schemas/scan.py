"""Scan request and response models.

Both frozen (CLAUDE.md §3 — immutable Pydantic by default).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl
from zynksec_schema import ScanProfile

from zynksec_api.schemas.finding import FindingRead
from zynksec_api.schemas.target import TargetSummary

ScanStatus = Literal["queued", "running", "completed", "failed"]


class ScanCreate(BaseModel):
    """Body of ``POST /api/v1/scans``.

    Exactly one of ``target_id`` or ``target_url`` must be provided
    — the router enforces this and surfaces both/neither as a
    canonical-envelope 422 (``scan_target_spec_conflict``).  Pydantic
    keeps both fields optional at the schema layer so the
    canonical envelope (rather than the default ``{"detail": [...]}``)
    is what callers see for the both/neither case.

    ``target_id`` (Phase 2 Sprint 1+) — id of an existing Target
    resource.  Recommended for new code; the handler resolves the
    URL + project from the Target row.

    ``target_url`` (legacy, still supported) — POST without ever
    creating a Target.  ``Scan.target_id`` stays null on these rows.
    The two paths exist concurrently so existing callers don't break;
    a future sprint can deprecate ``target_url`` once clients have
    migrated.

    ``project_id`` is optional in Phase 0; if absent, the handler
    looks up / creates the implicit "Local Dev" project (docs/04 §0.16).
    Ignored when ``target_id`` is given — the project comes from the
    Target row.

    ``scan_profile`` controls engine intensity.  The schema accepts
    every :class:`ScanProfile` value so the OpenAPI spec advertises
    them as valid for clients planning ahead.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_id: uuid.UUID | None = None
    target_url: HttpUrl | None = None
    project_id: uuid.UUID | None = None
    scan_profile: ScanProfile = ScanProfile.PASSIVE


class ScanRead(BaseModel):
    """Response body for ``POST /api/v1/scans`` and ``GET
    /api/v1/scans/{scan_id}``.

    ``findings`` is populated by the GET handler (the POST handler
    returns an empty list since the scan hasn't started yet).
    ``scan_profile`` echoes the engine intensity the scan was started
    under, in its enum wire form (``"PASSIVE"`` today).

    ``target`` (Phase 2 Sprint 1+) is the persistent Target this scan
    references, embedded as a compact summary.  ``null`` for scans
    created via the legacy ``target_url`` path or for rows that
    pre-date the Target migration.  ``target_url`` stays in the
    response so existing clients keep working — read it from
    ``target.url`` on new code.
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_url: str
    target: TargetSummary | None = None
    scan_profile: ScanProfile
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    findings: list[FindingRead] = Field(default_factory=list)
