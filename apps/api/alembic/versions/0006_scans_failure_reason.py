"""scans.failure_reason text nullable

Revision ID: 0006_scans_failure_reason
Revises: 0005_scans_assigned_queue
Create Date: 2026-04-29

Phase 2 debt-paydown: ``ScanRepository.mark_failed`` already accepts a
``reason`` argument from the worker but only logs it.  Persist it on
the Scan row so ``GET /api/v1/scans/{id}`` can surface
``failure_reason`` and operators can see why a scan failed without
grepping worker logs.

``text`` rather than a length-bounded ``String`` because plugin
rejection messages and exception strings can be longer than expected
(Postgres stores ``text`` and ``varchar`` identically — the only
difference is the bound check).  Nullable + no backfill: pre-existing
failed rows keep ``failure_reason IS NULL`` and the API surfaces that
faithfully ("we don't know" beats "we made up a reason").

No index — the column is informational only; we never filter scans
``WHERE failure_reason = ...`` in a hot path.

Reversible — the downgrade simply drops the column.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------- Alembic identifiers ----------
revision: str = "0006_scans_failure_reason"
down_revision: str | None = "0005_scans_assigned_queue"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("failure_reason", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "failure_reason")
