"""baseline: projects + scans + findings

Revision ID: 0001_baseline
Revises:
Create Date: 2026-04-23

First migration.  Creates the three Phase-0 tables (projects, scans,
findings) and their four Postgres ENUM types (scan_status,
severity_level, severity_confidence, lifecycle_status).  No raw SQL
beyond the two DROP TYPE lines in ``downgrade`` — Alembic's ``op.*``
helpers are used everywhere else (CLAUDE.md §6).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# ---------- Alembic identifiers ----------
revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---------- projects ----------
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
        sa.UniqueConstraint("name", name="uq_projects_name"),
    )

    # ---------- scans ----------
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "completed",
                "failed",
                name="scan_status",
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            ondelete="CASCADE",
            name="fk_scans_project_id_projects",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index(
        "ix_scans_project_id_status",
        "scans",
        ["project_id", "status"],
        unique=False,
    )

    # ---------- findings ----------
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "schema_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        # taxonomy
        sa.Column("taxonomy_zynksec_id", sa.String(length=64), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("owasp_top10", sa.String(length=16), nullable=True),
        # severity
        sa.Column(
            "severity_level",
            sa.Enum(
                "info",
                "low",
                "medium",
                "high",
                "critical",
                name="severity_level",
            ),
            nullable=False,
        ),
        sa.Column(
            "severity_confidence",
            sa.Enum("low", "medium", "high", name="severity_confidence"),
            nullable=False,
        ),
        # location
        sa.Column("location_url", sa.String(length=2048), nullable=False),
        sa.Column("location_method", sa.String(length=8), nullable=False),
        sa.Column("location_parameter", sa.String(length=255), nullable=True),
        # evidence
        sa.Column(
            "evidence_engine",
            sa.String(length=32),
            server_default="zap",
            nullable=False,
        ),
        sa.Column("evidence_rule_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_request", sa.Text(), nullable=False),
        sa.Column("evidence_response_excerpt", sa.Text(), nullable=False),
        # lifecycle
        sa.Column(
            "lifecycle_status",
            sa.Enum("open", "fixed", "ignored", name="lifecycle_status"),
            server_default="open",
            nullable=False,
        ),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            ondelete="CASCADE",
            name="fk_findings_scan_id_scans",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.UniqueConstraint(
            "scan_id",
            "fingerprint",
            name="uq_findings_scan_id_fingerprint",
        ),
    )


def downgrade() -> None:
    # Tables first (drops their FKs + indexes implicitly); then the ENUM
    # types Alembic auto-created.  DROP TYPE is the only raw-SQL path
    # here because Alembic lacks a dedicated drop_enum helper.
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("projects")
    op.execute(sa.text("DROP TYPE IF EXISTS lifecycle_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS severity_confidence"))
    op.execute(sa.text("DROP TYPE IF EXISTS severity_level"))
    op.execute(sa.text("DROP TYPE IF EXISTS scan_status"))
