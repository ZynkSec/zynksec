"""Semgrep plugin — SAST scanner alongside Gitleaks for kind=repo.

Profile flow (mirrors :class:`GitleaksPlugin` for symmetry — every
repo-scanner shares the clone + scan + parse + emit lifecycle):

    1. clone target.url shallow into ``/tmp/zynksec-scans/<scan_id>``
       via :func:`zynksec_scanners.repo.clone_shallow`.
    2. invoke ``semgrep --config p/security-audit --json --quiet
       --no-error <repo_path>`` in list-form subprocess.  Semgrep
       exits 0 on clean, 1 on findings, 2+ on real errors —
       ``--no-error`` flattens findings-present (1) into 0 so the
       only non-zero we see is genuine failure.
    3. parse the JSON report's ``results`` array; each entry maps to
       one :class:`CodeFinding` row with ``secret_kind`` and
       ``secret_hash`` left NULL (SAST patterns aren't secrets).
    4. teardown — same cloner ExitStack pattern as GitleaksPlugin.

Why ``p/security-audit``: curated, security-focused, ~150 rules,
deterministic enough to write integration assertions against.  The
broader ``auto`` mode pulls in style + maintenance rules that
would surface a flood of low-signal warnings.

CLAUDE.md rules in play:
  * §3 D — Dependency Inversion: the worker imports
    :class:`ScannerPlugin`, never :class:`SemgrepPlugin` directly.
  * §6 — Sprint 1 hardening preserved: ``stdin=subprocess.DEVNULL``
    on every subprocess; env passthrough via the cloner's
    ``_build_clone_env`` (Semgrep itself doesn't need GIT_*
    vars but inherits the same allow-list discipline).
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

#: Curated ``p/security-audit`` ruleset URL — ~150 security-focused
#: rules across Python, JS, Go, Java, etc.  Deterministic enough
#: to write tests against (the rules don't drift on every Semgrep
#: release the way the broader ``auto`` mode does).
_SEMGREP_RULESET: str = "p/security-audit"

#: Cap for the ``redacted_preview`` snippet copied from Semgrep's
#: ``extra.lines``.  The DB column is ``String(256)`` post-Sprint-2;
#: 200 leaves headroom for the ``"..."`` truncation marker without
#: hitting the column limit.
_PREVIEW_MAX_LEN: int = 200


# ---------- Severity mapping ----------
# Semgrep emits ``INFO`` / ``WARNING`` / ``ERROR`` in
# ``extra.severity``.  Map to our 4-level enum.  Critical is
# reserved for the highest-impact rules — ``p/security-audit`` rules
# carry an ``extra.metadata.impact`` field on the most-dangerous
# patterns (command injection, eval, deserialization).  When both
# ``severity == "ERROR"`` AND ``impact == "HIGH"`` align, escalate
# to critical.  Otherwise stick to the conservative mapping below.
_SEVERITY_BY_SEMGREP_LEVEL: dict[str, str] = {
    "INFO": "low",
    "WARNING": "medium",
    "ERROR": "high",
}


def _classify_severity(semgrep_severity: str, impact: str | None) -> str:
    """Map (semgrep_severity, impact) → our 4-level enum.

    The escalation to ``"critical"`` happens only when BOTH signals
    align: a rule with ``severity=ERROR`` AND
    ``metadata.impact=HIGH`` is the conjunction Semgrep uses for
    its highest-confidence dangerous patterns.  Single signals
    aren't enough — plenty of ``ERROR`` rules have ``impact=LOW``
    (style + maintenance), and ``impact=HIGH`` rules at WARNING
    level are still likely false-positives.
    """
    semgrep_severity_uc = (semgrep_severity or "").upper()
    base = _SEVERITY_BY_SEMGREP_LEVEL.get(semgrep_severity_uc, "low")
    if base == "high" and (impact or "").upper() == "HIGH":
        return "critical"
    return base


def _truncate_preview(lines: str) -> str:
    """Truncate ``extra.lines`` to fit the ``redacted_preview`` cap.

    Semgrep can return multi-line matches (e.g. multi-statement
    blocks); collapse to a single line via space-substitution so
    the preview stays single-row-readable in operator UIs.  Trail
    with ``...`` if truncation happened so callers know the
    snippet is partial.
    """
    flattened = " ".join((lines or "").splitlines())
    if len(flattened) <= _PREVIEW_MAX_LEN:
        return flattened
    return flattened[: _PREVIEW_MAX_LEN - 3] + "..."


@dataclass(frozen=True)
class SemgrepFinding:
    """Engine-native shape (one entry from Semgrep's JSON ``results``).

    Used between :meth:`SemgrepPlugin.run` and
    :meth:`SemgrepPlugin.normalize`; never persisted directly.
    """

    rule_id: str
    file_path: str
    line_number: int
    column_number: int | None
    severity: str  # already classified to our enum
    preview: str  # already truncated


class SemgrepPlugin(ScannerPlugin):
    """SAST repo-scanner alongside :class:`GitleaksPlugin`."""

    id = "semgrep"
    display_name = "Semgrep"
    supported_target_kinds: set[str] = {"repo"}
    supported_intensities: set[str] = {ScanProfile.PASSIVE.value}
    required_capabilities: set[str] = set()

    _CLONE_TIMEOUT_S: int = 60
    # Semgrep on a moderately-sized repo can take a couple of
    # minutes (rule loading + AST parsing + match execution).
    # 300 s caps runaway without truncating realistic scans.
    _SCAN_TIMEOUT_S: int = 300
    _SEMGREP_BIN: str = "semgrep"

    def __init__(self, semgrep_bin: str | None = None) -> None:
        # Override path for tests / alternative installs.  Production
        # reads from $PATH inside the code-worker image (Sprint 2
        # adds the binary).
        self._semgrep = semgrep_bin or self._SEMGREP_BIN
        self._exit_stack: ExitStack | None = None
        self._handle: RepoHandle | None = None
        self.engine_version: str = self._detect_engine_version()

    # ---- contract ----
    def supports(self, target: ScanTarget) -> bool:
        if target.kind not in self.supported_target_kinds:
            return False
        # Sprint 2 is PASSIVE-only — Semgrep has no intensity dial.
        return target.scan_profile.value in self.supported_intensities

    def prepare(self, target: ScanTarget) -> ScanContext:
        """Clone the repo into the per-scan temp directory."""
        self._verify_semgrep_available()
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
                "semgrep.prepare.clone_failed",
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
            raise RuntimeError("SemgrepPlugin.run called before prepare")

        cmd = [
            self._semgrep,
            "--config",
            _SEMGREP_RULESET,
            "--json",
            "--quiet",
            # ``--no-error`` flattens "findings present" exit-1 into
            # 0 so the only non-zero exit we see is real failure.
            # Findings-vs-clean is reflected in the JSON ``results``
            # array length, not the exit code.
            "--no-error",
            # Disable Semgrep's metric upload (privacy + offline-
            # friendliness; we don't want the worker to phone home
            # on every scan).
            "--metrics=off",
            # Disable interactive output entirely.
            "--disable-version-check",
            str(self._handle.path),
        ]

        _log.info(
            "semgrep.run.start",
            scan_id=str(context.target.scan_id),
            repo_path=str(self._handle.path),
            ruleset=_SEMGREP_RULESET,
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
            raise RuntimeError(f"semgrep scan timed out after {self._SCAN_TIMEOUT_S}s") from exc

        # With ``--no-error``, exit 0 = success (with or without
        # findings).  Anything non-zero is a real failure
        # (semgrep crash, malformed config, parse error).  Use the
        # generic-message discipline established in Sprint 1
        # cleanup Finding 5 — don't echo stderr into the
        # exception body since it could carry file content.
        if completed.returncode != 0:
            _log.debug(
                "semgrep.run.stderr",
                scan_id=str(context.target.scan_id),
                exit_code=completed.returncode,
                stderr_len=len(completed.stderr or ""),
            )
            raise RuntimeError(f"semgrep exited with code {completed.returncode}")

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("semgrep produced unparseable JSON output") from exc
        results = payload.get("results") or []

        _log.info(
            "semgrep.run.done",
            scan_id=str(context.target.scan_id),
            exit_code=completed.returncode,
            findings=len(results),
            ruleset=_SEMGREP_RULESET,
        )

        return RawScanResult(
            engine="semgrep",
            payload={"results": results},
        )

    def normalize(
        self,
        raw: RawScanResult,
        context: ScanContext,
    ) -> Iterator[Any]:
        """Yield engine-native :class:`SemgrepFinding` instances.

        Same pattern as :meth:`GitleaksPlugin.normalize` —
        the worker dispatches by ``plugin.id`` to
        :func:`code_findings_from_semgrep` for row construction.
        Yields ``Any`` to satisfy the abstract signature.

        Path normalisation: Semgrep emits ``entry["path"]`` as the
        absolute path of the matched file (e.g.
        ``/tmp/zynksec-scans/<scan_id>/repo/foo.py``).  Gitleaks
        emits repo-relative paths (e.g. ``foo.py``).  CodeFinding
        rows must use repo-relative paths for cross-scan dedup +
        operator-facing UIs to make sense — strip the repo-root
        prefix here so the persisted ``file_path`` looks the same
        regardless of which scanner produced it.
        """
        del context  # semgrep output is self-contained
        repo_root = self._handle.path if self._handle is not None else None
        for entry in raw.payload.get("results", []):
            try:
                rule_id = str(entry["check_id"])
                raw_path = str(entry["path"])
                # Path is relative-to-repo IF Semgrep emitted an
                # absolute path under the cloned repo root.  The
                # alternative — a relative path — survives unchanged.
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
                start = entry.get("start") or {}
                line_number = int(start.get("line") or 0)
                column_number_value = start.get("col")
                column_number = (
                    int(column_number_value) if column_number_value is not None else None
                )
                extra = entry.get("extra") or {}
                semgrep_severity = str(extra.get("severity") or "")
                metadata = extra.get("metadata") or {}
                impact = metadata.get("impact")
                preview_raw = str(extra.get("lines") or "")
            except (KeyError, TypeError, ValueError) as exc:
                _log.warning(
                    "semgrep.normalize.skipped_malformed_entry",
                    error=str(exc),
                )
                continue

            if not file_path or not rule_id:
                # Without rule_id or path the row has no useful
                # identity — skip rather than persist a half-shaped
                # finding.
                continue

            yield SemgrepFinding(
                rule_id=rule_id,
                file_path=file_path,
                line_number=line_number,
                column_number=column_number,
                severity=_classify_severity(semgrep_severity, impact),
                preview=_truncate_preview(preview_raw),
            )

    def teardown(self, context: ScanContext) -> None:
        """Close the cloner context manager — deletes the working tree."""
        del context
        if self._exit_stack is not None:
            try:
                self._exit_stack.close()
            except Exception as exc:  # noqa: BLE001 — best-effort
                _log.warning("semgrep.teardown.failed", error=str(exc))
            finally:
                self._exit_stack = None
                self._handle = None

    def health_check(self) -> HealthStatus:
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._semgrep, "--version"],
                check=False,
                timeout=10,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return HealthStatus(ok=False, message=f"semgrep unavailable: {exc}")
        if completed.returncode != 0:
            return HealthStatus(ok=False, message=(completed.stderr or "").strip()[:200])
        version = (completed.stdout or "").strip() or None
        return HealthStatus(ok=True, engine_version=version)

    # ---- helpers ----
    def _verify_semgrep_available(self) -> None:
        """Fail fast in :meth:`prepare` if the binary isn't on PATH."""
        if shutil.which(self._semgrep) is None:
            raise RuntimeError(
                f"semgrep binary {self._semgrep!r} not on PATH; "
                "is the code-worker image built from "
                "infra/docker/code-worker.Dockerfile (Sprint 2+)?",
            )

    def _detect_engine_version(self) -> str:
        """Run ``semgrep --version`` once and cache the parsed string.

        Mirrors :meth:`GitleaksPlugin._detect_engine_version`.  Falls
        back to ``"unknown"`` on any subprocess failure — version
        detection is observability-only.
        """
        if shutil.which(self._semgrep) is None:
            return "unknown"
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._semgrep, "--version"],
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


def code_findings_from_semgrep(
    findings: Iterable[SemgrepFinding],
    *,
    scan_id: uuid.UUID,
) -> list[dict[str, Any]]:
    """Map Semgrep engine-native findings to ``CodeFinding`` row kwargs.

    Sprint-2 mirror of
    :func:`zynksec_scanners.gitleaks.plugin.code_findings_from_gitleaks`.
    Semgrep findings are SAST patterns rather than secrets, so:

      * ``secret_kind`` is ``None``: no "secret category" applies;
        the rule_id + severity carry the full classification.
      * ``secret_hash`` is ``None``: no plaintext to hash.  Dedup
        on Semgrep findings happens naturally on
        (rule_id, file_path, line_number).
      * ``redacted_preview`` is the matched source-code snippet
        truncated to ``_PREVIEW_MAX_LEN`` chars — NOT a secret,
        so no actual redaction; the cap is for column-size
        bounding only.
      * ``commit_sha`` is ``None``: Semgrep doesn't surface
        commit context by default.
    """
    rows: list[dict[str, Any]] = []
    for f in findings:
        rows.append(
            {
                "scan_id": scan_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "column_number": f.column_number,
                "rule_id": f.rule_id,
                "secret_kind": None,
                "severity": f.severity,
                "redacted_preview": f.preview,
                "secret_hash": None,
                "commit_sha": None,
            },
        )
    return rows
