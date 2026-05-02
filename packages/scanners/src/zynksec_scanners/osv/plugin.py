"""OSV-Scanner plugin — dependency-vulnerability scanner alongside
Gitleaks (secrets) and Semgrep (SAST) for kind=repo.

Profile flow (mirrors :class:`SemgrepPlugin` for symmetry — every
repo-scanner shares the clone + scan + parse + emit lifecycle):

    1. clone target.url shallow into ``/tmp/zynksec-scans/<scan_id>``
       via :func:`zynksec_scanners.repo.clone_shallow`.
    2. invoke ``osv-scanner --format json --recursive <repo_path>``
       in list-form subprocess.  Exit codes:
         * 0 = no vulns found.
         * 1 = vulns found — NORMAL outcome, NOT a failure.
         * 2+ = real failure (network unreachable, bad lockfile
           parse, scanner crash).
    3. parse the JSON ``results[].packages[].groups[]`` array
       (groups are vuln-deduped CVSS-aware buckets — one finding
       per group, not per individual vulnerability ID, since
       aliases of the same advisory share a group).  For each
       group, find the matching ``vulnerabilities[]`` entry to
       extract the fix version.
    4. teardown — same cloner ExitStack pattern as the other
       repo-scanner plugins.

NETWORK REQUIREMENT (CLAUDE.md §6 caveat).  OSV-Scanner makes
outbound HTTPS calls to ``api.osv.dev`` for every package it
finds in the cloned lockfiles — a network-isolated worker
cannot use this scanner.  Egress for the code-worker container
is documented in ``infra/docker/code-worker.Dockerfile`` and
``docker-compose.yml`` (zynksec-core + zynksec-scan networks).
The Sprint 1 cleanup #4 env-passthrough lets corporate-proxy
operators reach OSV.dev via ``HTTPS_PROXY`` without code
changes.

Severity mapping uses CVSS v3 score buckets per the standard
ranges (NIST CVSS 3.x severity rating scale):

  * 0.0-3.9 → ``"low"``
  * 4.0-6.9 → ``"medium"``
  * 7.0-8.9 → ``"high"``
  * 9.0-10.0 → ``"critical"``

OSV emits ``max_severity`` as a string-encoded float (``"7.2"``)
on ``groups[]``.  When unparseable (older advisories without
CVSS scores), fall back to ``"medium"`` — neither suppressing
the finding nor raising it artificially.

CLAUDE.md rules in play (Sprint 1 cleanup discipline):
  * §3 D — Dependency Inversion: the worker imports
    :class:`ScannerPlugin`, never :class:`OsvScannerPlugin`
    directly.
  * §6 — ``stdin=subprocess.DEVNULL`` on every subprocess.
    Generic-message exception form
    (``"osv-scanner exited with code N"``) — no stderr echo,
    so attacker-controlled lockfile content can't leak into
    ``Scan.failure_reason``.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 — list-form only, no shell
import uuid
from collections.abc import Iterable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

import structlog

from zynksec_scanners.base import ScannerPlugin
from zynksec_scanners.repo import CloneError, RepoHandle, clone_shallow
from zynksec_scanners.types import (
    HealthStatus,
    RawScanResult,
    ScanContext,
    ScanProfile,
    ScanTarget,
)

_log = structlog.get_logger(__name__)

#: Cap for the ``redacted_preview`` snippet built from package
#: name + installed + fixed versions.  Same cap as Sprint 2 used
#: for Semgrep snippets (DB column is ``String(256)``); 200 leaves
#: headroom for the ``"..."`` truncation marker.
_PREVIEW_MAX_LEN: int = 200


def _classify_severity(max_severity: str | None) -> str:
    """Map OSV's ``max_severity`` string-encoded float → our 4-level enum.

    Falls back to ``"medium"`` for unparseable / missing values
    (older advisories without CVSS scores).  ``"medium"`` is the
    conservative middle — never suppresses a finding, never
    artificially escalates.

    NIST CVSS 3.x severity rating scale (the upstream ranges OSV
    follows):

      * 0.0-3.9   → low
      * 4.0-6.9   → medium
      * 7.0-8.9   → high
      * 9.0-10.0  → critical
    """
    if not max_severity:
        return "medium"
    try:
        score = float(max_severity)
    except (ValueError, TypeError):
        return "medium"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _build_preview(package_name: str, installed: str, fixed: str | None) -> str:
    """Build the ``redacted_preview`` snippet for an OSV finding.

    Format: ``<pkg>@<version> → <fix>`` (or ``"no fix"`` when
    OSV reports no fixed version yet).  Truncated to
    :data:`_PREVIEW_MAX_LEN` chars with a trailing ``"..."`` if
    the assembled string overflows — package names + versions
    are typically under 50 chars total, so truncation is a
    paranoid safety net rather than a routine code path.
    """
    fix_str = fixed if fixed else "no fix"
    preview = f"{package_name}@{installed} → {fix_str}"
    if len(preview) <= _PREVIEW_MAX_LEN:
        return preview
    return preview[: _PREVIEW_MAX_LEN - 3] + "..."


def _first_fixed_version(
    vulnerabilities: list[dict[str, Any]],
    *,
    target_id: str,
    package_name: str,
    package_ecosystem: str,
) -> str | None:
    """Walk a group's vulnerabilities to find the first ``fixed`` event.

    OSV's ``vulnerabilities[]`` carries the full advisory body for
    EACH ID in a group, with ``affected[]`` covering every
    package + ecosystem the advisory touches.  We want the
    ``fixed`` semver bound for the SPECIFIC (name, ecosystem)
    we're scanning — different packages in the same advisory may
    have different fix versions.

    Returns ``None`` if no advisory in this group has a fixed
    version recorded for our package.  In OSV terms that means
    the vulnerability is unfixed at HEAD of the affected branch
    — operators need to switch packages or pin to a known-clean
    older version.
    """
    for vuln in vulnerabilities:
        if vuln.get("id") != target_id:
            continue
        for affected in vuln.get("affected") or []:
            pkg = affected.get("package") or {}
            if pkg.get("name") != package_name or pkg.get("ecosystem") != package_ecosystem:
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if "fixed" in event:
                        return str(event["fixed"])
    return None


@dataclass(frozen=True)
class OsvFinding:
    """Engine-native shape (one entry per (package, group) pair).

    Used between :meth:`OsvScannerPlugin.run` and
    :meth:`OsvScannerPlugin.normalize`; never persisted directly.
    """

    rule_id: str  # Primary group ID (typically GHSA-...)
    file_path: str  # Lockfile path, repo-relative
    severity: str  # Already classified to our enum
    preview: str  # Already built / truncated


class OsvScannerPlugin(ScannerPlugin):
    """Dependency-vulnerability repo-scanner alongside
    :class:`GitleaksPlugin` and :class:`SemgrepPlugin`."""

    id = "osv-scanner"
    display_name = "OSV-Scanner"
    supported_target_kinds: set[str] = {"repo"}
    supported_intensities: set[str] = {ScanProfile.PASSIVE.value}
    required_capabilities: set[str] = {"network:api.osv.dev"}

    _CLONE_TIMEOUT_S: int = 60
    # Larger lockfiles can have 1000+ deps each requiring an
    # OSV API call.  600 s caps runaway without truncating
    # realistic scans (the gitfixture's 1-package lockfile
    # finishes in ~5 s).
    _SCAN_TIMEOUT_S: int = 600
    _OSV_BIN: str = "osv-scanner"

    def __init__(self, osv_bin: str | None = None) -> None:
        self._osv = osv_bin or self._OSV_BIN
        self._exit_stack: ExitStack | None = None
        self._handle: RepoHandle | None = None
        self.engine_version: str = self._detect_engine_version()

    # ---- contract ----
    def supports(self, target: ScanTarget) -> bool:
        if target.kind not in self.supported_target_kinds:
            return False
        return target.scan_profile.value in self.supported_intensities

    def prepare(self, target: ScanTarget) -> ScanContext:
        """Clone the repo into the per-scan temp directory."""
        self._verify_osv_available()
        try:
            stack = ExitStack()
            handle = stack.enter_context(
                clone_shallow(
                    target.url,
                    scan_id=str(target.scan_id),
                    timeout_s=self._CLONE_TIMEOUT_S,
                ),
            )
        except CloneError as exc:
            _log.error(
                "osv.prepare.clone_failed",
                scan_id=str(target.scan_id),
                error=str(exc),
            )
            raise

        self._exit_stack = stack
        self._handle = handle
        return ScanContext(
            target=target,
            metadata={"engine_version": self.engine_version, "repo_path": str(handle.path)},
        )

    def run(self, context: ScanContext) -> RawScanResult:
        if self._handle is None:
            raise RuntimeError("OsvScannerPlugin.run called before prepare")

        cmd = [
            self._osv,
            "--format",
            "json",
            "--recursive",
            str(self._handle.path),
        ]

        _log.info(
            "osv.run.start",
            scan_id=str(context.target.scan_id),
            repo_path=str(self._handle.path),
        )

        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                cmd,
                check=False,
                timeout=self._SCAN_TIMEOUT_S,
                capture_output=True,
                text=True,
                # Sprint 1 cleanup item #3 discipline: stdin closed.
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"osv-scanner timed out after {self._SCAN_TIMEOUT_S}s",
            ) from exc

        # Exit 0 = clean; exit 1 = vulns found (NORMAL).  Anything
        # else is a real failure — generic-message form per the
        # Sprint 1 Finding-5 hardening (no stderr echo into the
        # exception body, so lockfile content can't leak into
        # ``Scan.failure_reason``).
        if completed.returncode not in (0, 1):
            _log.debug(
                "osv.run.stderr",
                scan_id=str(context.target.scan_id),
                exit_code=completed.returncode,
                stderr_len=len(completed.stderr or ""),
            )
            raise RuntimeError(f"osv-scanner exited with code {completed.returncode}")

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("osv-scanner produced unparseable JSON output") from exc

        results = payload.get("results") or []
        # Total finding count for the structured log line.
        # Pre-counted from the parsed payload (don't re-decode).
        total_groups = sum(
            len(pkg.get("groups") or []) for r in results for pkg in (r.get("packages") or [])
        )
        _log.info(
            "osv.run.done",
            scan_id=str(context.target.scan_id),
            exit_code=completed.returncode,
            results=len(results),
            groups=total_groups,
        )

        return RawScanResult(
            engine="osv-scanner",
            payload={"results": results},
        )

    def normalize(
        self,
        raw: RawScanResult,
        context: ScanContext,
    ) -> Iterator[Any]:
        """Yield engine-native :class:`OsvFinding` instances.

        One finding per (package, group) pair — groups are OSV's
        already-deduplicated CVSS-aware bucket per advisory, so
        the alias chain (``GHSA-29mw-wpgm-hmr9 == CVE-2020-28500``)
        ends up as ONE finding, not two.

        Path normalisation: OSV-Scanner emits absolute lockfile
        paths under the cloned-repo root; strip the prefix to
        repo-relative for cross-scan dedup + UI consistency
        (same pattern as :meth:`SemgrepPlugin.normalize`).
        """
        del context  # OSV output is self-contained
        repo_root = self._handle.path if self._handle is not None else None
        for result in raw.payload.get("results", []):
            source = result.get("source") or {}
            raw_path = str(source.get("path") or "")
            if repo_root is not None:
                abs_repo = str(repo_root)
                if raw_path.startswith(abs_repo + "/"):
                    file_path = raw_path[len(abs_repo) + 1 :]
                elif raw_path == abs_repo:
                    file_path = ""
                else:
                    file_path = raw_path
            else:
                file_path = raw_path

            for pkg in result.get("packages") or []:
                package_block = pkg.get("package") or {}
                package_name = str(package_block.get("name") or "")
                package_version = str(package_block.get("version") or "")
                package_ecosystem = str(package_block.get("ecosystem") or "")
                vulnerabilities = pkg.get("vulnerabilities") or []

                # Dedup within a single scan: same (rule_id,
                # package, file_path) shouldn't surface twice.
                # In practice OSV's group structure already
                # de-dupes via aliases, but the seen-set is a
                # paranoid safety net against mis-shaped payloads.
                seen: set[tuple[str, str, str]] = set()
                for group in pkg.get("groups") or []:
                    ids = group.get("ids") or []
                    if not ids:
                        continue
                    rule_id = str(ids[0])
                    dedup_key = (rule_id, package_name, file_path)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    severity = _classify_severity(group.get("max_severity"))
                    fixed = _first_fixed_version(
                        vulnerabilities,
                        target_id=rule_id,
                        package_name=package_name,
                        package_ecosystem=package_ecosystem,
                    )
                    yield OsvFinding(
                        rule_id=rule_id,
                        file_path=file_path,
                        severity=severity,
                        preview=_build_preview(package_name, package_version, fixed),
                    )

    def teardown(self, context: ScanContext) -> None:
        """Close the cloner context manager — deletes the working tree."""
        del context
        if self._exit_stack is not None:
            try:
                self._exit_stack.close()
            except Exception as exc:  # noqa: BLE001 — best-effort
                _log.warning("osv.teardown.failed", error=str(exc))
            finally:
                self._exit_stack = None
                self._handle = None

    def health_check(self) -> HealthStatus:
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._osv, "--version"],
                check=False,
                timeout=10,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return HealthStatus(ok=False, message=f"osv-scanner unavailable: {exc}")
        if completed.returncode != 0:
            return HealthStatus(ok=False, message=(completed.stderr or "").strip()[:200])
        version = (completed.stdout or "").strip() or None
        return HealthStatus(ok=True, engine_version=version)

    # ---- helpers ----
    def _verify_osv_available(self) -> None:
        """Fail fast in :meth:`prepare` if the binary isn't on PATH."""
        if shutil.which(self._osv) is None:
            raise RuntimeError(
                f"osv-scanner binary {self._osv!r} not on PATH; "
                "is the code-worker image built from "
                "infra/docker/code-worker.Dockerfile (Sprint 3+)?",
            )

    def _detect_engine_version(self) -> str:
        """Run ``osv-scanner --version`` once and cache the parsed string.

        Falls back to ``"unknown"`` on any subprocess failure —
        version detection is observability-only.
        """
        if shutil.which(self._osv) is None:
            return "unknown"
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._osv, "--version"],
                check=False,
                timeout=5,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        if completed.returncode != 0:
            return "unknown"
        return (completed.stdout or "").strip() or "unknown"


def code_findings_from_osv(
    findings: Iterable[OsvFinding],
    *,
    scan_id: uuid.UUID,
) -> list[dict[str, Any]]:
    """Map OSV engine-native findings to ``CodeFinding`` row kwargs.

    Sprint 3 mirror of :func:`code_findings_from_semgrep`.  OSV
    findings are dependency vulnerabilities — none of the secret-
    related fields apply:

      * ``secret_kind`` / ``secret_hash`` — NULL (Sprint 2
        nullability).
      * ``commit_sha`` — NULL (osv-scanner doesn't surface
        commit context).
      * ``line_number`` — NULL (OSV findings are package-shaped,
        not line-shaped; Sprint 3 migration relaxed this column).
      * ``column_number`` — NULL (already nullable from Sprint 1).
      * ``redacted_preview`` — ``<pkg>@<ver> → <fix>`` (or
        ``no fix`` when unfixed).  Not actually redacted — pkg
        names and version strings aren't secrets, just length-
        bounded.
    """
    rows: list[dict[str, Any]] = []
    for f in findings:
        rows.append(
            {
                "scan_id": scan_id,
                "file_path": f.file_path,
                "line_number": None,
                "column_number": None,
                "rule_id": f.rule_id,
                "secret_kind": None,
                "severity": f.severity,
                "redacted_preview": f.preview,
                "secret_hash": None,
                "commit_sha": None,
            },
        )
    return rows
