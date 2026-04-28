"""Zynksec scanner plugins.

The abstract contract lives in :mod:`zynksec_scanners.base`.  Shared
types (ScanTarget, ScanContext, RawScanResult, HealthStatus) live in
:mod:`zynksec_scanners.types`.  Engine implementations live in sibling
sub-packages (``.zap``, future ``.nuclei``, ...).

Phase 2 Sprint 1 renamed the runtime parameter bundle from ``Target``
to ``ScanTarget``.  ``Target`` is re-exported as a deprecation alias
so out-of-tree plugins keep importing through the transition.
"""

from zynksec_scanners.base import ScannerPlugin
from zynksec_scanners.types import (
    HealthStatus,
    RawScanResult,
    ScanContext,
    ScanProfile,
    ScanTarget,
    Target,
    TargetKind,
)

__version__ = "0.0.0"

__all__ = [
    "HealthStatus",
    "RawScanResult",
    "ScanContext",
    "ScanProfile",
    "ScanTarget",
    "ScannerPlugin",
    "Target",
    "TargetKind",
    "__version__",
]
