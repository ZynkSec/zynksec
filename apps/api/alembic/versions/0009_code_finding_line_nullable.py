"""relax code_findings.line_number to nullable

Revision ID: 0009_code_finding_line_nullable
Revises: 0008_sprint2_semgrep_schema
Create Date: 2026-04-30

Phase 3 Sprint 3 schema groundwork.  OSV-Scanner emits findings
keyed to the affected PACKAGE in a lockfile, not to a specific
line — the underlying OSV API doesn't surface line numbers for
lockfile entries (verified by running ``osv-scanner --format
json`` against a synthesised ``package-lock.json``: output is
package-shaped, not file-line-shaped).

Pre-Sprint-3, ``code_findings.line_number`` was ``Integer NOT
NULL`` because the only producers were Gitleaks (precise line
of the matched secret) and Semgrep (precise line of the matched
SAST pattern).  Forcing OSV findings to carry a fake line
number would either lie (sentinel ``0`` / ``1``) or invite
brittle best-effort grep logic that drifts as lockfile formats
change.

Fix: drop NOT NULL.  Existing rows are unchanged (gitleaks +
semgrep both populate the column).  Future OSV-scanner rows
will leave it NULL.

Reversible — downgrade re-tightens NOT NULL.  The downgrade
will fail loudly if any rows have NULL ``line_number`` (i.e.
any OSV-scanner findings exist) — that's correct: rolling back
Sprint 3 should require explicit cleanup of the OSV-produced
rows first.

Audit of remaining ``code_findings`` NOT NULL columns for
future scanner families (Trivy, Grype, Syft):

  * ``file_path`` (NOT NULL).  Likely needs relaxation when
    Trivy ships — container-image scans can produce findings
    on a system-package CVE with no file context.  Don't relax
    now; flag for Sprint 4+.
  * ``severity`` (NOT NULL, ENUM).  Some upstream advisory
    databases emit "unrated" / "unknown" severity that doesn't
    map onto our 4-level enum.  Two future options: extend the
    enum with ``"unknown"``, or relax to nullable.  Don't decide
    now; flag for Sprint 4+.
  * ``rule_id`` (NOT NULL).  Every scanner produces SOME
    identifier (CVE, GHSA, semgrep rule path, gitleaks rule).
    Probably stays NOT NULL forever.
  * ``redacted_preview`` (NOT NULL).  Each scanner has SOMETHING
    to put here (snippet, pkg@ver line).  Probably stays NOT
    NULL forever.

Only ``line_number`` is relaxed in this sprint.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------- Alembic identifiers ----------
revision: str = "0009_code_finding_line_nullable"
down_revision: str | None = "0008_sprint2_semgrep_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "code_findings",
        "line_number",
        existing_type=sa.Integer(),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "code_findings",
        "line_number",
        existing_type=sa.Integer(),
        nullable=False,
    )
