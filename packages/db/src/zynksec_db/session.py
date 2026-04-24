"""Engine + session-factory helpers.

Intentionally stateless.  No cached engine, no module-level session —
callers build the engine once at app startup, then a session factory,
then scope sessions per request / per Celery task.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def engine_from_url(
    url: str,
    *,
    echo: bool = False,
    pool_pre_ping: bool = True,
) -> Engine:
    """Build a SQLAlchemy engine from a DSN.

    ``pool_pre_ping=True`` guards against stale connections after
    Postgres restarts (common in Docker Compose dev loops).  Pool
    sizing defaults are fine for a solo-dev footprint; tune per
    deployment in Phase 1.
    """

    return create_engine(url, echo=echo, pool_pre_ping=pool_pre_ping, future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a ``sessionmaker`` bound to ``engine``.

    ``expire_on_commit=False`` so ORM objects stay usable after a
    commit — important for the API, which commits and then serialises
    the row into a Pydantic response.
    """

    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
