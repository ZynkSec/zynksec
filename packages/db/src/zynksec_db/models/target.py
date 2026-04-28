"""Target — a persistent, named scan target inside a project.

Phase 2 Sprint 1 introduces this resource so callers can refer to a
target by id (``POST /api/v1/scans { "target_id": ... }``) instead of
re-typing the URL on every scan.  Targets accumulate scan history
and ownership-verification state (Phase 1 Sprint 4+) over time.

Distinct from :class:`zynksec_scanners.ScanTarget` — that's the
per-scan runtime parameter bundle the worker hands to plugins; this
is the persistent user-facing record that scans reference.  The two
share the ``url`` and ``kind`` field names but live in separate
namespaces (DB vs. plugin-runtime) and never cross paths in a single
file (CLAUDE.md §3 / §5).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from zynksec_db.base import Base


class Target(Base):
    """A named, persistent scan target belonging to a project.

    Same project may carry multiple targets with the same URL but
    different names (e.g. ``staging`` vs ``staging-debug-headers``),
    so URL is intentionally NOT unique within the project.  Name is
    unique per project — that's what gives the resource a stable
    human-readable handle.
    """

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_targets_project_id_name"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Stored as ``String(32)`` rather than a Postgres ENUM so adding a
    # kind in a future sprint doesn't need an ``ALTER TYPE`` — the
    # canonical value-set lives on
    # :data:`zynksec_scanners.types.TargetKind`.  Default ``"web_app"``
    # matches what every Phase 0/1 scan implicitly used.
    kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default="web_app",
        default="web_app",
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
