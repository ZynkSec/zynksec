"""Database engine + FastAPI session dependency.

Single engine per process (lazy-built from Settings).  Routers depend
on :func:`get_session` via ``Depends`` per CLAUDE.md §3 so handlers
never reach for a global session.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from zynksec_db import engine_from_url, make_session_factory

from zynksec_api.config import get_settings


@lru_cache(maxsize=1)
def _engine() -> Engine:
    """Single process-wide engine, lazy-built on first use."""
    return engine_from_url(get_settings().database_url)


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    return make_session_factory(_engine())


def get_session() -> Iterator[Session]:
    """FastAPI dependency — yields a session and closes it.

    Handlers that mutate data commit explicitly before returning.
    Transactions are per-request; no auto-commit-on-exit.
    """
    factory = _session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
