"""Zynksec scanner plugins.

The abstract contract lives in :mod:`zynksec_scanners.base`.  Shared
types (Target, ScanContext, RawScanResult, HealthStatus) live in
:mod:`zynksec_scanners.types`.  Engine implementations live in sibling
sub-packages (``.zap``, future ``.nuclei``, ...).
"""

from zynksec_scanners.base import ScannerPlugin
from zynksec_scanners.types import (
    HealthStatus,
    RawScanResult,
    ScanContext,
    ScanProfile,
    Target,
    TargetKind,
)

__version__ = "0.0.0"

__all__ = [
    "HealthStatus",
    "RawScanResult",
    "ScanContext",
    "ScanProfile",
    "ScannerPlugin",
    "Target",
    "TargetKind",
    "__version__",
]
