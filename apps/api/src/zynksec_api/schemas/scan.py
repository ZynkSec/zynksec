"""Scan request and response models.

Both frozen (CLAUDE.md §3 — immutable Pydantic by default).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from zynksec_api.schemas.finding import FindingRead

ScanStatus = Literal["queued", "running", "completed", "failed"]


class ScanCreate(BaseModel):
    """Body of ``POST /api/v1/scans``.

    ``project_id`` is optional in Phase 0; if absent, the handler
    looks up / creates the implicit "Local Dev" project (docs/04 §0.16).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_url: HttpUrl
    project_id: uuid.UUID | None = None


class ScanRead(BaseModel):
    """Response body for ``POST /api/v1/scans`` and ``GET
    /api/v1/scans/{scan_id}``.

    ``findings`` is populated by the GET handler (the POST handler
    returns an empty list since the scan hasn't started yet).
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_url: str
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    findings: list[FindingRead] = Field(default_factory=list)
