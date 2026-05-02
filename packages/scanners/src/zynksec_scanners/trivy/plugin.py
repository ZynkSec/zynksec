"""Trivy plugin — IaC misconfiguration scanner alongside Gitleaks
(secrets), Semgrep (SAST), and OSV-Scanner (deps) for kind=repo.

Profile flow (mirrors :class:`OsvScannerPlugin` for symmetry —
every repo-scanner shares the clone + scan + parse + emit
lifecycle):

    1. clone target.url shallow into ``/tmp/zynksec-scans/<scan_id>``
       via :func:`zynksec_scanners.repo.clone_shallow`.
    2. invoke ``trivy fs --scanners misconfig --format json --quiet
       --skip-policy-update --skip-db-update --offline-scan
       <repo_path>`` in list-form subprocess.  Exit codes:
         * 0 = scan succeeded (regardless of whether issues were
           found — Trivy doesn't fail-on-finding by default for
           misconfig).
         * non-zero = real failure (parse error, missing path,
           permission denied, scanner crash).
    3. parse the JSON ``Results[].Misconfigurations[]`` array.
       One ``CodeFinding`` per misconfiguration, deduped on
       (rule_id, file_path, line_number) within a scan.
    4. teardown — same cloner ExitStack pattern as the other
       repo-scanner plugins.

OFFLINE BY DESIGN.  Trivy ships its misconfig policies bundled
in the binary; ``--skip-policy-update --skip-db-update
--offline-scan`` together prevent ANY outbound network call at
scan time.  This is BOTH:
  * a security property — no window for upstream tampering
    mid-scan, no chance an attacker-controlled DNS hijack feeds
    a malicious policy;
  * a reliability property — works in air-gapped CI, doesn't
    flake when GitHub or AVD is down.

Severity mapping is a direct lowercase: Trivy emits
``LOW``/``MEDIUM``/``HIGH``/``CRITICAL`` on ``Misconfiguration.Severity``;
we map by ``str.lower()``.  ``UNKNOWN`` (or any unexpected value)
falls back to ``"medium"`` — neither suppressing nor escalating.

CLAUDE.md rules in play (Sprint 1 cleanup discipline):
  * §3 D — Dependency Inversion: the worker imports
    :class:`ScannerPlugin`, never :class:`TrivyPlugin` directly.
  * §6 — ``stdin=subprocess.DEVNULL`` on every subprocess.
    Generic-message exception form (``"trivy exited with code N"``)
    — no stderr echo, so attacker-controlled IaC content can't
    leak into ``Scan.failure_reason``.
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

#: Cap for the ``redacted_preview`` snippet built from
#: ``Misconfiguration.Title`` + ``.Description``.  Same cap as
#: Sprints 2 / 3 (DB column is ``String(256)``); 200 leaves
#: headroom for the ``"..."`` truncation marker.
_PREVIEW_MAX_LEN: int = 200

#: Trivy emits its built-in misconfig severities in upper-case;
#: the canonical 4-level enum we persist is lower-case.  Direct
#: 1:1 map — no boundary logic, no clamping, no float parsing.
_TRIVY_SEVERITY_MAP: dict[str, str] = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _classify_severity(trivy_severity: str | None) -> str:
    """Map Trivy's upper-case severity → our 4-level enum.

    Direct lowercase for the four canonical levels; ``"medium"``
    fallback for anything else (``UNKNOWN``, missing, malformed —
    Trivy occasionally emits ``UNKNOWN`` on rules without a
    severity attribute).  ``"medium"`` is the conservative middle
    — never suppresses a finding, never artificially escalates.
    """
    if not trivy_severity:
        return "medium"
    return _TRIVY_SEVERITY_MAP.get(trivy_severity.upper(), "medium")


def _build_preview(title: str, description: str) -> str:
    """Build the ``redacted_preview`` snippet for a misconfig finding.

    Format: ``"<Title>: <Description>"`` truncated to
    :data:`_PREVIEW_MAX_LEN` chars with a trailing ``"..."`` if
    overflow.  Both fields are operator-facing strings from
    Trivy's bundled rule metadata (e.g.
    ``"':latest' tag used: When using a 'FROM' statement..."``);
    nothing here is user-controlled, but truncation guards
    against pathological rule descriptions blowing up the row.

    Title alone (with no description) — rare but valid for some
    rules — formats as just the title (no trailing ``": "``).
    """
    title = title.strip()
    description = description.strip()
    if not title and not description:
        return "(no description)"
    if not description:
        preview = title
    elif not title:
        preview = description
    else:
        preview = f"{title}: {description}"
    if len(preview) <= _PREVIEW_MAX_LEN:
        return preview
    return preview[: _PREVIEW_MAX_LEN - 3] + "..."


def _start_line(misconfig: dict[str, Any]) -> int | None:
    """Extract the start line from ``Misconfiguration.CauseMetadata.StartLine``.

    Trivy provides StartLine for most rules but NOT all — e.g.
    ``DS-0026`` ("No HEALTHCHECK defined") fires on the *absence*
    of a directive, so there's no line to point at.  Return
    ``None`` in that case so the persisted row honours migration
    0009 (``code_findings.line_number`` nullable).

    Trivy uses ``0`` as a sentinel for "no line available" on
    some rules; treat ``0`` and missing identically — line 1 is
    the lowest valid line for a 1-indexed file.
    """
    cause = misconfig.get("CauseMetadata") or {}
    raw = cause.get("StartLine")
    if not isinstance(raw, int) or raw <= 0:
        return None
    return raw


@dataclass(frozen=True)
class TrivyFinding:
    """Engine-native shape (one entry per Trivy misconfiguration).

    Used between :meth:`TrivyPlugin.run` and
    :meth:`TrivyPlugin.normalize`; never persisted directly.
    """

    rule_id: str  # e.g., DS-0001, KSV-0017, AVD-AWS-0086
    file_path: str  # Repo-relative target path
    line_number: int | None  # CauseMetadata.StartLine or None
    severity: str  # Already lowercased to our enum
    preview: str  # Already built / truncated


class TrivyPlugin(ScannerPlugin):
    """IaC-misconfiguration repo-scanner.  Sibling of
    :class:`GitleaksPlugin`, :class:`SemgrepPlugin`,
    :class:`OsvScannerPlugin`."""

    id = "trivy"
    display_name = "Trivy (IaC misconfig)"
    supported_target_kinds: set[str] = {"repo"}
    supported_intensities: set[str] = {ScanProfile.PASSIVE.value}
    # Empty by design — offline-only; ``--skip-policy-update
    # --skip-db-update --offline-scan`` makes the scanner work
    # against a network-isolated worker.  This is part of the
    # Sprint-4 contract; tests assert these flags appear in the
    # constructed argv.
    required_capabilities: set[str] = set()

    _CLONE_TIMEOUT_S: int = 60
    # Misconfig scans are CPU-bound on the policy engine and
    # have no network or DB dependencies; even large repos run
    # in well under a minute.  300 s is a generous safety cap.
    _SCAN_TIMEOUT_S: int = 300
    _TRIVY_BIN: str = "trivy"

    #: The flags that make this plugin OFFLINE.  Pulled out as a
    #: tuple so the integration test can introspect them and
    #: assert they always appear in the constructed argv —
    #: a future "small refactor" that drops one of them would
    #: silently re-enable network calls.
    OFFLINE_FLAGS: tuple[str, ...] = (
        "--skip-policy-update",
        "--skip-db-update",
        "--offline-scan",
    )

    def __init__(self, trivy_bin: str | None = None) -> None:
        self._trivy = trivy_bin or self._TRIVY_BIN
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
        self._verify_trivy_available()
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
                "trivy.prepare.clone_failed",
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

    def build_argv(self, repo_path: str) -> list[str]:
        """Build the trivy fs argv.  Exposed for the integration
        test that asserts the offline flags are always present —
        if a future change drops ``--offline-scan`` the test fails
        without the test having to spin up a network-isolated
        container.
        """
        return [
            self._trivy,
            "fs",
            "--scanners",
            "misconfig",
            "--format",
            "json",
            "--quiet",
            *self.OFFLINE_FLAGS,
            repo_path,
        ]

    def run(self, context: ScanContext) -> RawScanResult:
        if self._handle is None:
            raise RuntimeError("TrivyPlugin.run called before prepare")

        cmd = self.build_argv(str(self._handle.path))

        _log.info(
            "trivy.run.start",
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
                f"trivy timed out after {self._SCAN_TIMEOUT_S}s",
            ) from exc

        # Trivy doesn't fail-on-finding for misconfig by default;
        # 0 means "scan succeeded", regardless of whether issues
        # were found.  Anything non-zero is a real failure —
        # generic-message form per the Sprint 1 Finding-5
        # hardening (no stderr echo into the exception body).
        if completed.returncode != 0:
            _log.debug(
                "trivy.run.stderr",
                scan_id=str(context.target.scan_id),
                exit_code=completed.returncode,
                stderr_len=len(completed.stderr or ""),
            )
            raise RuntimeError(f"trivy exited with code {completed.returncode}")

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("trivy produced unparseable JSON output") from exc

        results = payload.get("Results") or []
        # Total misconfig count for the structured log line.
        total_misconfigs = sum(len(r.get("Misconfigurations") or []) for r in results)
        _log.info(
            "trivy.run.done",
            scan_id=str(context.target.scan_id),
            exit_code=completed.returncode,
            results=len(results),
            misconfigurations=total_misconfigs,
        )

        return RawScanResult(
            engine="trivy",
            payload={"Results": results},
        )

    def normalize(
        self,
        raw: RawScanResult,
        context: ScanContext,
    ) -> Iterator[Any]:
        """Yield engine-native :class:`TrivyFinding` instances.

        One finding per misconfiguration, deduped on
        (rule_id, file_path, line_number) within a scan — the
        same rule firing on different lines (or different files)
        IS a different finding and surfaces separately.

        Path normalisation: Trivy emits ``Result.Target`` already
        relative to the scan path it was given (so for ``trivy
        fs <repo_path>`` the Target is the repo-relative path
        directly — no prefix-stripping needed).  Defensive
        handling: if a future Trivy version emits absolute paths,
        strip the repo-root prefix the same way OSV / Semgrep do.
        """
        del context  # Trivy output is self-contained
        repo_root = self._handle.path if self._handle is not None else None
        seen: set[tuple[str, str, int | None]] = set()
        for result in raw.payload.get("Results", []):
            raw_path = str(result.get("Target") or "")
            file_path = self._normalize_path(raw_path, repo_root)

            for misconfig in result.get("Misconfigurations") or []:
                rule_id = str(misconfig.get("ID") or "")
                if not rule_id:
                    continue
                line_number = _start_line(misconfig)
                dedup_key = (rule_id, file_path, line_number)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                yield TrivyFinding(
                    rule_id=rule_id,
                    file_path=file_path,
                    line_number=line_number,
                    severity=_classify_severity(misconfig.get("Severity")),
                    preview=_build_preview(
                        str(misconfig.get("Title") or ""),
                        str(misconfig.get("Description") or ""),
                    ),
                )

    def teardown(self, context: ScanContext) -> None:
        """Close the cloner context manager — deletes the working tree."""
        del context
        if self._exit_stack is not None:
            try:
                self._exit_stack.close()
            except Exception as exc:  # noqa: BLE001 — best-effort
                _log.warning("trivy.teardown.failed", error=str(exc))
            finally:
                self._exit_stack = None
                self._handle = None

    def health_check(self) -> HealthStatus:
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._trivy, "--version"],
                check=False,
                timeout=10,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return HealthStatus(ok=False, message=f"trivy unavailable: {exc}")
        if completed.returncode != 0:
            return HealthStatus(ok=False, message=(completed.stderr or "").strip()[:200])
        version = (completed.stdout or "").splitlines()[0].strip() if completed.stdout else None
        return HealthStatus(ok=True, engine_version=version)

    # ---- helpers ----
    @staticmethod
    def _normalize_path(raw_path: str, repo_root: Any) -> str:
        """Strip an absolute repo-root prefix if Trivy emits one.

        Trivy 0.70 emits Target relative to the scan path, so
        this is a no-op in practice.  Kept as a defensive shim
        in case future versions revert to absolute paths (we'd
        rather degrade gracefully than ship absolute paths into
        the database, which would break cross-scan dedup).
        """
        if not raw_path:
            return ""
        if repo_root is None:
            return raw_path
        abs_repo = str(repo_root)
        if raw_path.startswith(abs_repo + "/"):
            return raw_path[len(abs_repo) + 1 :]
        if raw_path == abs_repo:
            return ""
        return raw_path

    def _verify_trivy_available(self) -> None:
        """Fail fast in :meth:`prepare` if the binary isn't on PATH."""
        if shutil.which(self._trivy) is None:
            raise RuntimeError(
                f"trivy binary {self._trivy!r} not on PATH; "
                "is the code-worker image built from "
                "infra/docker/code-worker.Dockerfile (Sprint 4+)?",
            )

    def _detect_engine_version(self) -> str:
        """Run ``trivy --version`` once and cache the parsed string.

        Falls back to ``"unknown"`` on any subprocess failure —
        version detection is observability-only.

        ``trivy --version`` prints multi-line output (Version: ...,
        Vulnerability DB: ..., etc.); we use the first line as the
        compact version string.
        """
        if shutil.which(self._trivy) is None:
            return "unknown"
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._trivy, "--version"],
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
        first_line = (completed.stdout or "").splitlines()[:1]
        return first_line[0].strip() if first_line else "unknown"


def code_findings_from_trivy(
    findings: Iterable[TrivyFinding],
    *,
    scan_id: uuid.UUID,
) -> list[dict[str, Any]]:
    """Map Trivy engine-native findings to ``CodeFinding`` row kwargs.

    Sprint 4 mirror of :func:`code_findings_from_osv`.  Trivy
    findings are IaC misconfigurations — none of the secret-
    related fields apply:

      * ``secret_kind`` / ``secret_hash`` — NULL (Sprint 2
        nullability).
      * ``commit_sha`` — NULL (trivy doesn't surface commit
        context for misconfig).
      * ``line_number`` — Trivy ``CauseMetadata.StartLine`` when
        present, NULL otherwise (e.g., DS-0026 "no HEALTHCHECK"
        fires on absence).  Migration 0009 already made this
        column nullable.
      * ``column_number`` — NULL (Trivy doesn't provide column
        metadata for misconfigs).
      * ``redacted_preview`` — ``"<Title>: <Description>"``.
        Not actually redacted — Trivy's bundled rule metadata
        is operator-facing copy, not user-controlled content.
    """
    rows: list[dict[str, Any]] = []
    for f in findings:
        rows.append(
            {
                "scan_id": scan_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
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
