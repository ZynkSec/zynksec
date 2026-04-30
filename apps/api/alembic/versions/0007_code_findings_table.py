"""code_findings table for Phase 3 repo scanners

Revision ID: 0007_code_findings_table
Revises: 0006_scans_failure_reason
Create Date: 2026-04-29

Phase 3 Sprint 1: gitleaks lands the first scanner family that
reports file-shaped findings (file_path + line_number) instead of
HTTP-shaped findings (URL + method + parameter).  A separate table
keeps both schemas tight; the alternative — many-nullable-columns
on the existing ``findings`` table — was explicitly rejected in the
sprint plan because it couples lifecycles that don't share fix
semantics.

Critical: this table NEVER stores plaintext secrets.  The
``redacted_preview`` column carries first-4 + last-4 chars only;
``secret_hash`` carries SHA-256 of the raw value for cross-scan
dedup.  Plugins must strip the raw secret from gitleaks output
before constructing rows.

Indexes:
  * ``ix_code_findings_scan_id_severity`` — hot path for
    ``GET /api/v1/scans/{id}`` + dashboard severity bucketing.
  * ``ix_code_findings_secret_hash`` — cross-scan dedup question
    ("have we seen this secret in a prior scan, anywhere?").

Reversible — downgrade drops the table, the enum type, and both
indexes (Postgres drops indexes implicitly with the table; the
enum type needs an explicit DROP TYPE).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# ---------- Alembic identifiers ----------
revision: str = "0007_code_findings_table"
down_revision: str | None = "0006_scans_failure_reason"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_SEVERITY_ENUM_NAME = "code_finding_severity"


def upgrade() -> None:
    op.create_table(
        "code_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("file_path", sa.String(length=2048), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("column_number", sa.Integer(), nullable=True),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("secret_kind", sa.String(length=64), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "low",
                "medium",
                "high",
                "critical",
                name=_SEVERITY_ENUM_NAME,
            ),
            nullable=False,
        ),
        sa.Column("redacted_preview", sa.String(length=128), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("commit_sha", sa.String(length=40), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            ondelete="CASCADE",
            name="fk_code_findings_scan_id_scans",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_code_findings"),
    )
    op.create_index(
        "ix_code_findings_scan_id_severity",
        "code_findings",
        ["scan_id", "severity"],
        unique=False,
    )
    op.create_index(
        "ix_code_findings_secret_hash",
        "code_findings",
        ["secret_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_code_findings_secret_hash", table_name="code_findings")
    op.drop_index("ix_code_findings_scan_id_severity", table_name="code_findings")
    op.drop_table("code_findings")
    # Postgres-specific cleanup: Postgres ENUM types are independent
    # of any one column — drop the type explicitly so a re-up
    # doesn't trip ``DuplicateObject``.  On other backends
    # (SQLite / MySQL / etc.) ``sa.Enum.drop`` is a no-op because
    # those dialects don't carry a separate type registry.  Zynksec
    # only supports Postgres, so this branch is the only one
    # exercised in CI; the explicit drop here documents that
    # constraint for any future port.
    sa.Enum(name=_SEVERITY_ENUM_NAME).drop(op.get_bind(), checkfirst=True)
