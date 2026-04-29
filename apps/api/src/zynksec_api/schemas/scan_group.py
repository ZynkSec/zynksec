"""ScanGroup request and response models — Phase 2 Sprint 2.

A ScanGroup is the parent of N child Scan rows produced by a single
``POST /api/v1/scan-groups`` call against multiple targets.  The
on-the-wire shape mirrors the design notes in
:mod:`zynksec_db.models.scan_group`: ``status`` rolls up the
children's terminal states; ``summary`` is a per-status count
computed on read.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from zynksec_schema import ScanProfile

from zynksec_api.schemas.scan import ScanRead

ScanGroupStatus = Literal["queued", "running", "completed", "partial_failure", "failed"]


class ScanGroupCreate(BaseModel):
    """Body of ``POST /api/v1/scan-groups``.

    ``target_ids`` is the canonical input — at least one, at most 50.
    Pydantic enforces the length bounds and emits a default 422 for
    those (the empty-list case is the "Pydantic min_length"
    treatment the prompt asks for explicitly).  Duplicate ids are
    detected at the router layer so callers get the canonical
    ``duplicate_target_ids`` envelope rather than the default
    ``{"detail": [...]}`` shape.

    ``scan_profile`` is applied uniformly to every child.  Mixed
    profiles per group is out of scope — a future sprint can add
    per-target overrides.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)
    name: str | None = None
    scan_profile: ScanProfile = ScanProfile.PASSIVE
    project_id: uuid.UUID | None = None


class ScanGroupSummary(BaseModel):
    """Per-status counts of the group's child Scan rows.

    ``total`` is the sum of the per-status buckets.  Computed on
    read so the value never drifts from the underlying Scan rows.
    """

    model_config = ConfigDict(frozen=True)

    total: int
    queued: int
    running: int
    completed: int
    failed: int


class ScanGroupRead(BaseModel):
    """Response body for ``POST /api/v1/scan-groups`` and the
    ``GET /api/v1/scan-groups/...`` endpoints.

    ``child_scan_ids`` lists the children's ids in their creation
    order — clients can ``GET /api/v1/scans/{id}`` for each to drill
    in.  ``summary`` carries the same information aggregated.

    ``child_scans`` (Phase 2 debt-paydown) embeds the same children
    as full :class:`ScanRead` objects so a single GET surfaces every
    child's status / ``failure_reason`` / queue assignment without an
    extra round-trip per child.  ``findings`` on each embedded
    ScanRead is intentionally empty — clients fetch
    ``GET /api/v1/scans/{id}`` to drill into findings, the same way
    POST /api/v1/scans returns ``findings=[]`` immediately after
    enqueue.
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    project_id: uuid.UUID
    name: str | None = None
    scan_profile: ScanProfile
    status: ScanGroupStatus
    child_scan_ids: list[uuid.UUID] = Field(default_factory=list)
    child_scans: list[ScanRead] = Field(default_factory=list)
    summary: ScanGroupSummary
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
