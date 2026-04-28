"""targets table + scans.target_id FK

Revision ID: 0003_targets_table
Revises: 0002_scans_scan_profile
Create Date: 2026-04-27

Phase 2 Sprint 1: introduces the persistent ``targets`` table that
the new ``/api/v1/targets`` CRUD surface manages, plus a nullable
``scans.target_id`` FK so a Scan can link back to its Target.

No backfill of pre-existing ``scans`` rows — Sprint-1 callers using
``POST /api/v1/scans { target_url: ... }`` keep working with
``target_id IS NULL`` (the response's ``target`` field is ``null``
for those legacy rows).  A future sprint can write the backfill
once we have ownership-verification rules to decide which Project a
historical ``target_url`` belongs in.

The FK uses ``ON DELETE RESTRICT`` so an operator can't delete a
Target out from under a scan that references it; the API surfaces
that as a canonical ``409 target_has_scans`` error before the FK
ever fires, but the DB constraint is the safety belt.

Both ``upgrade`` and ``downgrade`` are reversible — verified locally
via ``alembic upgrade head`` then ``alembic downgrade -1``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# ---------- Alembic identifiers ----------
revision: str = "0003_targets_table"
down_revision: str | None = "0002_scans_scan_profile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---------- targets ----------
    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column(
            "kind",
            sa.String(length=32),
            server_default="web_app",
            nullable=False,
        ),
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
            name="fk_targets_project_id_projects",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_targets"),
        sa.UniqueConstraint(
            "project_id",
            "name",
            name="uq_targets_project_id_name",
        ),
    )
    op.create_index(
        "ix_targets_project_id",
        "targets",
        ["project_id"],
        unique=False,
    )

    # ---------- scans.target_id ----------
    op.add_column(
        "scans",
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_scans_target_id_targets",
        "scans",
        "targets",
        ["target_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_scans_target_id",
        "scans",
        ["target_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_target_id", table_name="scans")
    op.drop_constraint("fk_scans_target_id_targets", "scans", type_="foreignkey")
    op.drop_column("scans", "target_id")

    op.drop_index("ix_targets_project_id", table_name="targets")
    op.drop_table("targets")
