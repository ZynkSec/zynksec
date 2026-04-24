"""Alembic environment.

Online migrations only — Phase 0 has no offline use case.  DATABASE_URL
comes from the process environment so the same migration harness works
in Docker (env_file) and bare ``uv run alembic`` (from a .env or shell).

Imports ``Base.metadata`` from :mod:`zynksec_db` so future autogenerate
diffs against the real model definitions.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from zynksec_db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    fallback = config.get_main_option("sqlalchemy.url") or ""
    if not fallback or "placeholder" in fallback:
        raise RuntimeError(
            "DATABASE_URL is not set.  Copy .env.example to .env or export "
            "DATABASE_URL before running alembic.",
        )
    return fallback


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against a live DB connection."""

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
