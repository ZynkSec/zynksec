"""ORM models — Project, Target, Scan, Finding."""

from zynksec_db.models.finding import Finding
from zynksec_db.models.project import Project
from zynksec_db.models.scan import Scan
from zynksec_db.models.target import Target

__all__ = ["Finding", "Project", "Scan", "Target"]
