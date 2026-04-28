"""scans.assigned_queue varchar(32) nullable

Revision ID: 0005_scans_assigned_queue
Revises: 0004_scan_groups_table
Create Date: 2026-04-26

Phase 2 Sprint 3: multi-instance ZAP fan-out.  Each Scan now records
which Celery queue it was dispatched to (``zap_q_1`` / ``zap_q_2`` /
... up to ``ZAP_INSTANCE_COUNT``).  Stored as a free-form short
string rather than a Postgres ENUM so adding a third pair is a
``.env`` bump + compose edit, not an ``ALTER TYPE``.

Nullable + no backfill — pre-existing rows from Sprint 1/2 carry
``assigned_queue IS NULL`` and the API treats that as "legacy
single-queue scan; surface as-is."  No index: the column is purely
informational (queue distribution audits + integration-test
assertions); we never filter scans WHERE assigned_queue = X in a hot
path.

Reversible — the downgrade simply drops the column.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------- Alembic identifiers ----------
revision: str = "0005_scans_assigned_queue"
down_revision: str | None = "0004_scan_groups_table"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("assigned_queue", sa.String(length=32), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "assigned_queue")
