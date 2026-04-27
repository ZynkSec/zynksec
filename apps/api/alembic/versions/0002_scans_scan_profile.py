"""scans.scan_profile column

Revision ID: 0002_scans_scan_profile
Revises: 0001_baseline
Create Date: 2026-04-26

Adds ``scan_profile`` to the ``scans`` table to back the new
``ScanProfile`` API parameter (Phase 1 Sprint 1).  Existing rows get
``'PASSIVE'`` via ``server_default`` — backward-compatible with
already-persisted scans (CLAUDE.md §8 / DoD).

Stored as ``String(32)`` rather than a Postgres ENUM so adding
profiles in future sprints doesn't need an ``ALTER TYPE`` — the
canonical value-set lives on ``zynksec_schema.ScanProfile`` and the
API rejects unknown values at the Pydantic boundary.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------- Alembic identifiers ----------
revision: str = "0002_scans_scan_profile"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "scan_profile",
            sa.String(length=32),
            nullable=False,
            server_default="PASSIVE",
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "scan_profile")
