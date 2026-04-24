"""Finding repository."""

from __future__ import annotations

from sqlalchemy.orm import Session

from zynksec_db.models.finding import Finding
from zynksec_db.repositories.base import Repository


class FindingRepository(Repository[Finding]):
    """Persist normalised :class:`Finding`s.  Week 3's worker uses
    :meth:`add_many` once ZAP returns real results."""

    model = Finding

    def add_many(self, session: Session, findings: list[Finding]) -> list[Finding]:
        """Batch insert.  Caller owns the transaction."""
        session.add_all(findings)
        session.flush()
        return findings
