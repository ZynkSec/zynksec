"""Abstract scanner plugin contract.

Every engine Zynksec integrates (ZAP, Nuclei, testssl, Subfinder, ...)
subclasses :class:`ScannerPlugin`.  The worker depends on this
abstraction, never on a concrete engine (CLAUDE.md §3 — D: Dependency
Inversion).  Adding a new engine is subclass + Dockerfile + YAML config
(docs/03 §6, docs/04 §0.10).

Phase 0 Week 1 ships signatures only; all methods raise
``NotImplementedError``.  Week 3 lands the ZAP implementation; Phase 1
adds ``pause``, ``cancel``, and ``resume`` once we know what ZAP allows
mid-scan (docs/04 §0.10).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

# Phase-0 placeholder aliases.  Concrete types land with their sibling
# packages — Target/Scan with the DB models (Week 2), Finding with the
# shared-schema Finding module (Week 3), and engine-native
# ScanContext/RawScanResult inside each plugin subpackage.  Kept as
# ``Any`` at this boundary so downstream packages can introduce their
# real types without forcing a breaking edit here.
Target = Any
ScanContext = Any
RawScanResult = Any
RawFinding = Any
Finding = Any
HealthStatus = Any


class ScannerPlugin(ABC):
    """Abstract contract every Zynksec scanner engine implements.

    Class-level attributes carry the engine's static metadata; instance
    methods drive the scan lifecycle.  The orchestrator guarantees a
    pre-verified target, a writable working directory, and gated egress
    (docs/03 §6.2).  In return the subclass promises to respect the
    rate-limit config, exit cleanly on cancellation, and never write
    outside its working directory (docs/03 §6.3).
    """

    # ---- Static metadata (subclasses override) ----
    id: str
    display_name: str
    engine_version: str
    supported_target_kinds: set[str]
    supported_intensities: set[str]
    required_capabilities: set[str]

    # ---- Lifecycle ----
    @abstractmethod
    def supports(self, target: Target) -> bool:
        """Return True iff this engine can scan this target kind."""
        raise NotImplementedError

    @abstractmethod
    def prepare(self, scan: ScanContext) -> ScanContext:
        """Build engine-specific config and validate reachability.

        Returns an opaque context the orchestrator passes to
        :meth:`run` and :meth:`teardown`.
        """
        raise NotImplementedError

    @abstractmethod
    def run(self, context: ScanContext) -> RawScanResult:
        """Execute the scan against the prepared context.

        Blocking in Phase 0; Phase 1+ streams raw findings via an async
        iterator (docs/03 §6.1).
        """
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: RawScanResult) -> Iterator[Finding]:
        """Map engine-native output to canonical :class:`Finding`s.

        One raw finding MAY yield zero or many Findings.  Evidence
        request/response/proof must be attached here.
        """
        raise NotImplementedError

    @abstractmethod
    def teardown(self, context: ScanContext) -> None:
        """Release engine resources and clear transient sessions."""
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """Report whether the engine container is reachable and
        responsive right now."""
        raise NotImplementedError
