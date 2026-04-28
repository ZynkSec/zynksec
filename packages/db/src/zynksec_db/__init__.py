"""Zynksec SQLAlchemy models + repositories.

Shared by apps/api and apps/worker.  Keep this package free of any
HTTP-framework or Celery specifics — it is pure data access.
"""

from zynksec_db.base import Base
from zynksec_db.models import Finding, Project, Scan, ScanGroup, Target
from zynksec_db.repositories import (
    FindingRepository,
    Repository,
    ScanGroupRepository,
    ScanRepository,
    TargetRepository,
)
from zynksec_db.session import engine_from_url, make_session_factory

__version__ = "0.0.0"

__all__ = [
    "Base",
    "Finding",
    "FindingRepository",
    "Project",
    "Repository",
    "Scan",
    "ScanGroup",
    "ScanGroupRepository",
    "ScanRepository",
    "Target",
    "TargetRepository",
    "__version__",
    "engine_from_url",
    "make_session_factory",
]
