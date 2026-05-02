"""Zynksec scanner plugins.

The abstract contract lives in :mod:`zynksec_scanners.base`.  Shared
types (ScanTarget, ScanContext, RawScanResult, HealthStatus) live in
:mod:`zynksec_scanners.types`.  Engine implementations live in sibling
sub-packages (``.zap``, future ``.nuclei``, ...).

The runtime parameter bundle is :class:`ScanTarget` (the
``Target = ScanTarget`` deprecation alias was removed in Phase 2
Sprint 1 — the bare ``Target`` name now belongs to the persistent
ORM resource in :mod:`zynksec_db`).  Out-of-tree plugins must import
``ScanTarget`` directly.
"""

from zynksec_scanners.base import ScannerPlugin
from zynksec_scanners.registry import (
    SCANNER_GITLEAKS,
    SCANNER_OSV,
    SCANNER_SEMGREP,
    SCANNER_ZAP,
    UnknownScanner,
    default_scanner_for,
    resolve_scanner,
    scanner_for_kind,
    scanners_for_kind,
)
from zynksec_scanners.types import (
    HealthStatus,
    RawScanResult,
    ScanContext,
    ScanProfile,
    ScanTarget,
    TargetKind,
)

__version__ = "0.0.0"

__all__ = [
    "HealthStatus",
    "RawScanResult",
    "SCANNER_GITLEAKS",
    "SCANNER_OSV",
    "SCANNER_SEMGREP",
    "SCANNER_ZAP",
    "ScanContext",
    "ScanProfile",
    "ScanTarget",
    "ScannerPlugin",
    "TargetKind",
    "UnknownScanner",
    "__version__",
    "default_scanner_for",
    "resolve_scanner",
    "scanner_for_kind",
    "scanners_for_kind",
]
