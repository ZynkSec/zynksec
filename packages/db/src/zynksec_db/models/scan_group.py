"""ScanGroup — a multi-target scan request.

Phase 2 Sprint 2: when a caller wants to scan N targets in one
request, the API persists a single ``ScanGroup`` parent row and N
child :class:`Scan` rows linked by ``scans.scan_group_id``.  The
worker processes the children serially against the existing single
ZAP instance (concurrency is still pinned at 1 — multi-instance
fan-out is Sprint 3).

The group's ``status`` rolls up across its children:

    queued            — created, worker hasn't picked it up yet
    running           — at least one child running, none terminal yet
    completed         — every child completed
    failed            — every child failed
    partial_failure   — mix of completed + failed; group is "done" but
                        the caller should look at child statuses

The ``summary`` (counts by child status) is NOT stored on the group
row — it's computed on read from the child rows.  Two reasons:

    1. No race between the worker writing per-child status and a
       reader hitting the group endpoint mid-update.
    2. Single source of truth — child Scan rows already carry their
       status; storing a derived counter would invite drift.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from zynksec_db.base import Base


class ScanGroup(Base):
    """A multi-target scan request — one parent, N child Scan rows."""

    __tablename__ = "scan_groups"
    __table_args__ = (
        Index(
            "ix_scan_groups_project_id_created_at",
            "project_id",
            "created_at",
        ),
    )

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
    name: Mapped[str | None] = mapped_column(String(255), nullable=True, default=None)
    # Free-form short string (matches the existing ``Scan.scan_profile``
    # convention — see scan.py).  Canonical value-set lives on
    # :class:`zynksec_schema.ScanProfile`.
    scan_profile: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PASSIVE",
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "queued",
            "running",
            "completed",
            "partial_failure",
            "failed",
            name="scan_group_status",
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
