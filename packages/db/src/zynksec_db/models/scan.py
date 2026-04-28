"""Scan — one scan invocation against a target URL."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from zynksec_db.base import Base

if TYPE_CHECKING:
    from zynksec_db.models.scan_group import ScanGroup
    from zynksec_db.models.target import Target


class Scan(Base):
    """One scan: belongs to a project, targets a URL, moves through a
    strict state machine (queued -> running -> completed | failed)."""

    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_project_id_status", "project_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Phase 2 Sprint 1: optional FK to the persistent Target resource.
    # Nullable — pre-existing rows + the legacy ``target_url`` POST path
    # both leave it null.  ``ON DELETE RESTRICT`` so an operator can't
    # delete a Target out from under a scan that references it
    # (the API surfaces this as 409 ``target_has_scans``).
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    # Eager-load via JOIN.  ``GET /api/v1/scans/{id}`` returns the
    # target embedded in the response body, and the scan-create
    # handler reads ``scan.target.url`` immediately after persistence;
    # avoiding a second SELECT keeps the hot path single-query.
    target: Mapped[Target | None] = relationship("Target", lazy="joined")
    # Phase 2 Sprint 2: optional FK to the parent ScanGroup when this
    # scan is a child of a multi-target request.  Null for
    # ``POST /scans`` single-target scans (legacy + Sprint-1 paths).
    # ``ON DELETE CASCADE`` because a child Scan has no meaning
    # without its group — deleting the group nukes its children
    # cleanly.  ``lazy="select"`` (default) since GET /scans/{id}
    # responses don't embed the parent group; clients that want it
    # GET /scan-groups/{id} explicitly.
    #
    # NB: the ``ix_scans_scan_group_id`` index is created in the
    # 0004 Alembic migration — that migration is the source of truth
    # for index management, so we don't redundantly declare
    # ``index=True`` here.
    scan_group_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scan_groups.id", ondelete="CASCADE"),
        nullable=True,
    )
    scan_group: Mapped[ScanGroup | None] = relationship("ScanGroup")
    # Stored as a free-form short string rather than a Postgres ENUM so
    # adding profiles in future sprints (Sprint 2: SAFE_ACTIVE,
    # Sprint 3: AGGRESSIVE) doesn't need a Postgres ALTER TYPE — the
    # canonical value-set lives on :class:`zynksec_schema.ScanProfile`.
    scan_profile: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default="PASSIVE",
        default="PASSIVE",
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "queued",
            "running",
            "completed",
            "failed",
            name="scan_status",
        ),
        nullable=False,
        default="queued",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
