"""Abstract repository base.

Subclasses bind :attr:`model` and layer on domain-specific operations
(state-machine transitions, batch inserts, ...).  The base class gives
everyone the same minimal CRUD surface so repeat boilerplate stays out
of the domain classes.
"""

from __future__ import annotations

import uuid
from typing import Any, Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from zynksec_db.base import Base

T = TypeVar("T", bound=Base)


class Repository(Generic[T]):
    """Base repository.  Subclasses override :attr:`model`."""

    model: type[T]

    def get(self, session: Session, id_: uuid.UUID) -> T | None:
        """Return the row with ``id == id_`` or ``None`` if absent."""
        return session.get(self.model, id_)

    def add(self, session: Session, instance: T) -> T:
        """Attach ``instance`` to the session and flush.  Caller commits."""
        session.add(instance)
        session.flush()
        return instance

    def list(self, session: Session, **filters: Any) -> list[T]:
        """Return every row matching every ``column == value`` filter.

        Intentionally minimal — ordering, pagination, and richer
        predicates land per-repository in Phase 1.
        """
        stmt = select(self.model)
        for column_name, value in filters.items():
            stmt = stmt.where(getattr(self.model, column_name) == value)
        return list(session.execute(stmt).scalars().all())
