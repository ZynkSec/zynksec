"""CodeFinding response model + converter from the SQLAlchemy row.

Phase 3 Sprint 1 wire shape for repo-scanner findings.  Distinct
from :class:`FindingRead` (HTTP-shaped) — code findings carry file
paths and line numbers, never URL + method + parameter.

``secret_hash`` deliberately omitted from the wire shape: the hash
exists for cross-scan dedup (a server-side concern) and exposing
it would let a caller reconstruct match-set membership without
auth.  ``redacted_preview`` is the operator-facing evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from zynksec_db import CodeFinding as CodeFindingRow

CodeSeverity = Literal["low", "medium", "high", "critical"]


class CodeFindingRead(BaseModel):
    """Wire shape for one secret detected by a repo scanner."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    file_path: str
    line_number: int
    column_number: int | None
    rule_id: str
    secret_kind: str
    severity: CodeSeverity
    redacted_preview: str
    commit_sha: str | None
    created_at: datetime


def code_finding_from_row(row: CodeFindingRow) -> CodeFindingRead:
    """SQLAlchemy row -> wire shape.  Drops ``secret_hash`` by design."""
    return CodeFindingRead(
        id=row.id,
        scan_id=row.scan_id,
        file_path=row.file_path,
        line_number=row.line_number,
        column_number=row.column_number,
        rule_id=row.rule_id,
        secret_kind=row.secret_kind,
        severity=row.severity,  # type: ignore[arg-type]
        redacted_preview=row.redacted_preview,
        commit_sha=row.commit_sha,
        created_at=row.created_at,
    )
