"""Declarative Base with a Zynksec-wide metadata naming convention.

Alembic reads names from this metadata, so every auto-generated
constraint gets a predictable, readable name (CLAUDE.md §4):

- ``ix_<table>_<col0..colN>``  — indexes
- ``uq_<table>_<col0..colN>``  — unique constraints
- ``ck_<table>_<constraint>``  — check constraints
- ``fk_<table>_<col>_<ref>``   — foreign keys
- ``pk_<table>``                — primary keys
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

_NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Shared DeclarativeBase — every Zynksec ORM model subclasses this."""

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)
