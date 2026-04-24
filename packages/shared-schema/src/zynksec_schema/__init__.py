"""Zynksec canonical schemas.

The Phase-0 ``Finding`` model and the frozen fingerprint formula both
live here.  Everything else in Zynksec that touches a Finding imports
from this package — no engine-native shapes ever leak past the scanner
plugin boundary (CLAUDE.md §5).
"""

from zynksec_schema.finding import (
    Confidence,
    Engine,
    Evidence,
    Finding,
    Lifecycle,
    LifecycleStatus,
    Location,
    Severity,
    SeverityLevel,
    Taxonomy,
)
from zynksec_schema.fingerprint import compute_fingerprint, normalize_url

__version__ = "0.0.0"

__all__ = [
    "Confidence",
    "Engine",
    "Evidence",
    "Finding",
    "Lifecycle",
    "LifecycleStatus",
    "Location",
    "Severity",
    "SeverityLevel",
    "Taxonomy",
    "__version__",
    "compute_fingerprint",
    "normalize_url",
]
