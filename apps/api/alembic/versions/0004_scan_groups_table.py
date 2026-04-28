"""scan_groups table + scans.scan_group_id FK

Revision ID: 0004_scan_groups_table
Revises: 0003_targets_table
Create Date: 2026-04-28

Phase 2 Sprint 2: introduces the persistent ``scan_groups`` table
that owns the per-scan rows for a multi-target request, plus a
nullable ``scans.scan_group_id`` FK so a Scan can link back to its
parent group.

No backfill of pre-existing ``scans`` rows — Phase 1 / Sprint-1
single-target scans keep ``scan_group_id IS NULL``.  The API
surfaces those scans the same way it always did (``GET /scans/{id}``);
group-aware listings (``GET /scan-groups/{id}``) only see scans
created via ``POST /scan-groups``.

The FK uses ``ON DELETE CASCADE`` because a child Scan is
meaningless without its group: deleting the group nukes its
children atomically.  This is the inverse of the ``scans.target_id``
FK (which is ``ON DELETE RESTRICT`` because Targets have an
independent identity that scans merely reference).

Both ``upgrade()`` and ``downgrade()`` are reversible — verified
locally via ``alembic upgrade head`` then ``alembic downgrade -1``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# ---------- Alembic identifiers ----------
revision: str = "0004_scan_groups_table"
down_revision: str | None = "0003_targets_table"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---------- scan_groups ----------
    op.create_table(
        "scan_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("scan_profile", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "completed",
                "partial_failure",
                "failed",
                name="scan_group_status",
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
            name="fk_scan_groups_project_id_projects",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scan_groups"),
    )
    op.create_index(
        "ix_scan_groups_project_id_created_at",
        "scan_groups",
        ["project_id", "created_at"],
        unique=False,
    )

    # ---------- scans.scan_group_id ----------
    op.add_column(
        "scans",
        sa.Column(
            "scan_group_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_scans_scan_group_id_scan_groups",
        "scans",
        "scan_groups",
        ["scan_group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_scans_scan_group_id",
        "scans",
        ["scan_group_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_scan_group_id", table_name="scans")
    op.drop_constraint(
        "fk_scans_scan_group_id_scan_groups",
        "scans",
        type_="foreignkey",
    )
    op.drop_column("scans", "scan_group_id")

    op.drop_index("ix_scan_groups_project_id_created_at", table_name="scan_groups")
    op.drop_table("scan_groups")
    # The ``scan_group_status`` ENUM type Alembic auto-created when the
    # table came up — drop it explicitly so the downgrade is fully
    # reversible (the same pattern used in the baseline migration).
    op.execute(sa.text("DROP TYPE IF EXISTS scan_group_status"))
