"""scans.scanner column + relax code_findings nullables for Semgrep

Revision ID: 0008_sprint2_semgrep_schema
Revises: 0007_code_findings_table
Create Date: 2026-04-29

Phase 3 Sprint 2: introduce SemgrepPlugin alongside GitleaksPlugin
as the second SAST scanner over kind=repo Targets.  Two structural
changes:

  1. ``scans.scanner`` (new column, varchar(64), NULL) — records
     which scanner ran this scan.  Nullable for backward compat:
     pre-Sprint-2 rows stay NULL, plus future POSTs that omit
     ``scanner`` resolve to the per-kind default (Gitleaks for
     kind=repo, ZAP for kind=web_app/api) at dispatch time and
     persist the resolved name back here.  Free-form short
     string (not a Postgres ENUM) so adding a future scanner —
     trivy, OSV, syft, grype — doesn't need an ``ALTER TYPE``.
     The canonical value-set lives in
     :mod:`zynksec_scanners.registry`.

  2. ``code_findings.secret_kind`` and ``code_findings.secret_hash``
     are dropped from NOT NULL.  These columns are gitleaks-
     specific (cross-scan dedup of repeated secrets via SHA-256
     and the human-readable secret-type category respectively).
     Semgrep findings are SAST patterns, not committed secrets —
     there's no plaintext to hash and no "secret kind" applies.
     Forcing values would either be lies (synthesised "Semgrep
     finding" labels that aren't really secret kinds) or category
     errors (bogus hash of the matched code line).  NULL is the
     honest signal.

  3. ``code_findings.redacted_preview`` widens from ``String(128)``
     to ``String(256)``.  Gitleaks previews are fixed at 12 chars
     (``first-4 + **** + last-4``); Semgrep previews are truncated
     matched-source-code lines and need ~200 chars to be useful.
     256 leaves headroom while still bounding row size.

No backfill: gitleaks rows committed pre-migration remain
``NOT NULL`` valid; the constraint relaxation only affects new
inserts.

Reversible — downgrade re-tightens the NOT NULL constraints AND
narrows the column type back to ``String(128)``.  The downgrade
will fail loudly if any rows have NULL in ``secret_hash`` or
``secret_kind`` (i.e. any Semgrep findings exist) — that's
correct: rolling back Sprint 2 should require explicit cleanup
of the Semgrep-produced rows first.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------- Alembic identifiers ----------
revision: str = "0008_sprint2_semgrep_schema"
down_revision: str | None = "0007_code_findings_table"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("scanner", sa.String(length=64), nullable=True),
    )
    op.alter_column(
        "code_findings",
        "secret_kind",
        existing_type=sa.String(length=64),
        nullable=True,
    )
    op.alter_column(
        "code_findings",
        "secret_hash",
        existing_type=sa.String(length=64),
        nullable=True,
    )
    op.alter_column(
        "code_findings",
        "redacted_preview",
        existing_type=sa.String(length=128),
        type_=sa.String(length=256),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Re-narrowing redacted_preview to 128 chars is safe iff no
    # row exceeds 128 chars.  Rolling back Sprint 2 with Semgrep
    # findings present would fail here — that's deliberate.
    op.alter_column(
        "code_findings",
        "redacted_preview",
        existing_type=sa.String(length=256),
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    op.alter_column(
        "code_findings",
        "secret_hash",
        existing_type=sa.String(length=64),
        nullable=False,
    )
    op.alter_column(
        "code_findings",
        "secret_kind",
        existing_type=sa.String(length=64),
        nullable=False,
    )
    op.drop_column("scans", "scanner")
