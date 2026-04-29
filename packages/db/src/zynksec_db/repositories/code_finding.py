"""CodeFinding repository — Phase 3 Sprint 1.

Sibling of :class:`FindingRepository`; shares the same minimal CRUD
surface (CLAUDE.md §3 — domain code never sees raw sessions).  The
extra methods here exist because the gitleaks worker writes findings
in batches (one ``add_many`` per scan) and the API surfaces both the
per-scan list and a count for the dashboard summary.

``find_existing_hashes`` is the cross-scan dedup hook for Phase 3
Sprint 7+ (rule-based finding lifecycle).  Sprint 1 doesn't call it
yet — the method is here so the dedup plumbing isn't bolted on
later when the lifecycle layer arrives.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zynksec_db.models.code_finding import CodeFinding
from zynksec_db.repositories.base import Repository


class CodeFindingRepository(Repository[CodeFinding]):
    """Persist and read :class:`CodeFinding` rows."""

    model = CodeFinding

    def add_many(
        self,
        session: Session,
        findings: list[CodeFinding],
    ) -> list[CodeFinding]:
        """Bulk insert.  Caller owns the transaction.

        Mirrors :meth:`FindingRepository.add_many` so the worker's
        scan-execution path can stay symmetrical between scanner
        families.
        """
        session.add_all(findings)
        session.flush()
        return findings

    def list_by_scan(self, session: Session, scan_id: uuid.UUID) -> list[CodeFinding]:
        """Return every CodeFinding belonging to ``scan_id``."""
        stmt = select(CodeFinding).where(CodeFinding.scan_id == scan_id)
        return list(session.execute(stmt).scalars().all())

    def count_by_scan(self, session: Session, scan_id: uuid.UUID) -> int:
        """Cheap COUNT — used by the scan-read response summary."""
        stmt = select(func.count()).select_from(CodeFinding).where(CodeFinding.scan_id == scan_id)
        return int(session.execute(stmt).scalar_one())

    def find_existing_hashes(
        self,
        session: Session,
        secret_hashes: list[str],
    ) -> set[str]:
        """Return the subset of ``secret_hashes`` already present anywhere.

        Cross-scan, cross-project — the dedup question is "have we
        ever seen this exact value before?".  Not used in Sprint 1;
        wired in for the Phase 3 Sprint 7+ lifecycle work.
        """
        if not secret_hashes:
            return set()
        stmt = select(CodeFinding.secret_hash).where(CodeFinding.secret_hash.in_(secret_hashes))
        return {row for row in session.execute(stmt).scalars().all()}
