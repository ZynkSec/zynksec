"""Finding — Phase-0 subset of the canonical Finding schema.

Columns here follow ``docs/04_phase0_scaffolding.md`` §0.11.  The full
Finding v1 schema (``docs/03_architecture.md`` §5) lands in Phase 1.

The fingerprint formula is FROZEN (docs/04 §0.11):
changing it requires bumping ``schema_version`` and writing a
migration plan.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from zynksec_db.base import Base


class Finding(Base):
    """A single normalised finding attached to a scan."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "fingerprint",
            name="uq_findings_scan_id_fingerprint",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # ---------- Taxonomy ----------
    taxonomy_zynksec_id: Mapped[str] = mapped_column(String(64), nullable=False)
    cwe: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owasp_top10: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # ---------- Severity ----------
    severity_level: Mapped[str] = mapped_column(
        Enum("info", "low", "medium", "high", "critical", name="severity_level"),
        nullable=False,
    )
    severity_confidence: Mapped[str] = mapped_column(
        Enum("low", "medium", "high", name="severity_confidence"),
        nullable=False,
    )

    # ---------- Location ----------
    location_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    location_method: Mapped[str] = mapped_column(String(8), nullable=False)
    location_parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ---------- Evidence ----------
    evidence_engine: Mapped[str] = mapped_column(String(32), nullable=False, default="zap")
    evidence_rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_request: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_response_excerpt: Mapped[str] = mapped_column(Text, nullable=False)

    # ---------- Lifecycle ----------
    lifecycle_status: Mapped[str] = mapped_column(
        Enum("open", "fixed", "ignored", name="lifecycle_status"),
        nullable=False,
        default="open",
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
