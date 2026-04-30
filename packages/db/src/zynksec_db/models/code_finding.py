"""CodeFinding — repo-scanner finding row (Phase 3).

Repo-scanner output (gitleaks first; semgrep added in Sprint 2;
trivy / OSV / syft / grype follow) is shaped around files +
line numbers, not HTTP requests + responses.  Forcing it into the
existing ``findings`` table would mean half-a-dozen nullable HTTP
columns on every code row and half-a-dozen nullable file columns on
every ZAP row — many-nullable-columns sprawl that couples lifecycles
that have nothing in common.

Separate table.  Same Scan FK so a Scan still owns N findings; the
two tables are queried separately by the API depending on the
scanner family.

Hard security rule (CLAUDE.md §6, §10): the **plaintext secret
value is never persisted**.  Gitleaks emits the raw match in its
JSON output; the plugin strips it before constructing the row.
What we store is enough to triage and dedup without ever turning
the database into a credential dump:

  * ``redacted_preview`` — operator-facing evidence snippet.  The
    shape depends on the scanner:
      - Gitleaks: first-4 + ``****`` + last-4 of the secret
        (always 12 chars; the masked-portion length isn't a
        side-channel).
      - Semgrep: the matched source-code line(s) truncated to the
        column cap.  Semgrep matches aren't secrets, so the
        snippet is not redacted — just length-bounded.
    Column is ``String(256)`` to accommodate the longer Semgrep
    snippets while still bounding the row size.
  * ``secret_hash`` — SHA-256 of the raw secret value.  Gitleaks-
    specific (Sprint 2 made it nullable; Semgrep findings carry
    NULL).  Same secret found in two scans collides on the hash,
    so dedup is exact.  Hash is one-way; recovering the secret
    from the hash is no easier than brute-forcing the underlying
    entropy.
  * ``secret_kind`` — Gitleaks-specific human-readable category
    (``"AWS access key"``, ``"GitHub personal access token"``,
    ...).  Sprint 2 made it nullable; Semgrep findings carry
    NULL because rule_id + severity carry the full classification.

The dedup index sits on ``secret_hash`` alone (NOT
``(scan_id, secret_hash)``) because the dedup question crosses
scans — "have we seen this exact secret before, anywhere?" — not
just "in this scan".  Per-scan indexing is on
``(scan_id, severity)`` to power the count-by-scan + severity
filter the API surfaces on read.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from zynksec_db.base import Base


class CodeFinding(Base):
    """One secret detected by a repo-scanner plugin (gitleaks for now).

    Owns no lifecycle / fingerprint columns yet — the canonical
    :class:`zynksec_schema.Finding` shape is HTTP-shaped and doesn't
    apply.  Phase 3 Sprint 7+ will introduce a ``CodeFinding``
    Pydantic model in ``packages/shared-schema`` and align lifecycle
    semantics across both finding families; this sprint keeps the
    columns minimal and the API contract small.
    """

    __tablename__ = "code_findings"
    __table_args__ = (
        # Hot path: ``GET /api/v1/scans/{id}`` filters by scan_id and
        # the dashboard segments by severity; the composite index
        # covers both without a second secondary index.
        Index("ix_code_findings_scan_id_severity", "scan_id", "severity"),
        # Cross-scan dedup question — "have we seen this secret in a
        # prior scan of any project?" — answered by hash lookup.
        Index("ix_code_findings_secret_hash", "secret_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ---------- Location (file + line, not URL + method) ----------
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    column_number: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ---------- Rule metadata ----------
    # Engine-native rule id (e.g. ``aws-access-token``,
    # ``github-pat``).  Stored as-is so triage UIs can link to the
    # gitleaks rule reference.
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # Human-readable category derived from the rule (e.g. "AWS
    # access key", "GitHub personal access token").  Stable across
    # gitleaks rule-id renames, which is the value triagers care
    # about.  Phase 3 Sprint 2: nullable.  Gitleaks always populates
    # this; Semgrep findings (SAST patterns, not secrets) leave it
    # NULL — the rule_id + severity carry the full classification,
    # and a ``secret_kind`` would be a category error.
    secret_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)

    severity: Mapped[str] = mapped_column(
        Enum(
            "low",
            "medium",
            "high",
            "critical",
            name="code_finding_severity",
        ),
        nullable=False,
    )

    # ---------- Redacted evidence ----------
    # ``redacted_preview`` carries the operator-facing snippet — for
    # gitleaks: first-4 + ``****`` + last-4 of the secret; for
    # Semgrep: the matched source-code line(s) truncated to the
    # column cap (Semgrep matches aren't secrets so the snippet is
    # not redacted, just length-bounded).  Always populated.
    #
    # ``secret_hash`` is gitleaks-specific (cross-scan dedup of
    # repeated secrets via SHA-256).  Phase 3 Sprint 2: nullable —
    # Semgrep findings leave it NULL (no plaintext secret to hash;
    # SAST patterns dedup naturally on rule_id + file_path + line).
    redacted_preview: Mapped[str] = mapped_column(String(256), nullable=False)
    secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Optional commit fingerprint when gitleaks captured it; null on
    # ``--no-git`` style scans (Phase 3 Sprint 1 only ever clones
    # with a working tree, but later sprints may scan packed
    # tarballs and lose commit context).
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
