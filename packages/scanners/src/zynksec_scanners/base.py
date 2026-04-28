"""Abstract scanner plugin contract.

Every engine Zynksec integrates (ZAP, Nuclei, testssl, ...) subclasses
:class:`ScannerPlugin`.  The worker depends on this abstraction, never
on a concrete engine (CLAUDE.md §3 — D: Dependency Inversion).  Adding
a new engine is subclass + Dockerfile + compose entry.

Contract per ``docs/04_phase0_scaffolding.md`` §0.10.  Phase 1 adds
``pause()``, ``cancel()``, and ``resume()`` once we know what each
engine allows mid-scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from zynksec_schema import Finding

from zynksec_scanners.types import HealthStatus, RawScanResult, ScanContext, ScanTarget


class ScannerPlugin(ABC):
    """Abstract contract every Zynksec scanner engine implements.

    Class-level attributes carry the engine's static metadata.  The
    six lifecycle methods below are the whole Phase-0 surface.
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
    def supports(self, target: ScanTarget) -> bool:
        """Return True iff this engine can scan this target."""

    @abstractmethod
    def prepare(self, target: ScanTarget) -> ScanContext:
        """Build engine-specific state and validate reachability.

        Returns an opaque context the orchestrator passes to
        :meth:`run`, :meth:`normalize`, and :meth:`teardown`.
        """

    @abstractmethod
    def run(self, context: ScanContext) -> RawScanResult:
        """Execute the scan.  Blocking in Phase 0."""

    @abstractmethod
    def normalize(
        self,
        raw: RawScanResult,
        context: ScanContext,
    ) -> Iterator[Finding]:
        """Map engine-native output to canonical Findings.

        Takes the context so it can read ``target.project_id`` /
        ``scan_id`` while fingerprinting.
        """

    @abstractmethod
    def teardown(self, context: ScanContext) -> None:
        """Release engine resources and clear transient state.

        Best-effort: implementations should log-and-swallow errors
        rather than propagate (a failed cleanup must not mask a
        successful scan).
        """

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """Report whether the engine is reachable and responsive."""
