"""ORM models — the three tables Phase 0 Week 2 persists."""

from zynksec_db.models.finding import Finding
from zynksec_db.models.project import Project
from zynksec_db.models.scan import Scan

__all__ = ["Finding", "Project", "Scan"]
