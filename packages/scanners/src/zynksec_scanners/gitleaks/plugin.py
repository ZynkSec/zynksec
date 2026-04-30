"""Gitleaks plugin — repo-scanner ScannerPlugin implementation.

Profile flow (single intensity in Sprint 1; later sprints may add
``--no-git`` working-tree-only mode for deeper history scans):

    1. clone target.url shallow into ``/tmp/zynksec-scans/<scan_id>``
       via :func:`zynksec_scanners.repo.clone_shallow`.
    2. invoke ``gitleaks detect --source <repo> --report-format json``
       in the cloned directory; gitleaks exits 1 when secrets are
       found and 0 when none are — exit 1 is NOT a failure for us.
    3. parse the JSON report; redact the raw secret value, hash it,
       map the rule_id to a Zynksec severity, emit a CodeFinding.
    4. teardown deletes the working tree (the cloner's context
       manager handles this — the plugin only owns the gitleaks
       lifecycle).

CLAUDE.md rules in play:
  * §3 D — Dependency Inversion: the worker imports
    :class:`ScannerPlugin`, never :class:`GitleaksPlugin` directly.
  * §5 — RawScanResult is engine-native; the canonical Finding
    shape (:class:`CodeFinding` here) is what the worker persists.
  * §6 — never log the raw secret value.  Structlog calls below
    pass only ``rule_id``, ``file_path``, and ``line_number``.

The plugin owns the gitleaks lifecycle, NOT the canonical Finding
fingerprint.  ``CodeFinding`` rows are constructed directly (no
HTTP-shaped Finding round-trip); the worker's
:func:`apps.worker.tasks._execution.execute_scan` branches on the
plugin family and calls a different repository.
"""

from __future__ import annotations

import hashlib
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


# ---------- Severity mapping ----------
# Gitleaks rule ids are kebab-case ``family-specific``; categories
# below classify by FAMILY prefix (always trailing-dash so
# ``"jwt"`` doesn't accidentally match a future ``"jwtbomb"`` rule).
# A separate exact-name table covers the gitleaks rules whose
# canonical name has no family suffix (``jwt``, ``generic-api-key``).
# The mapping is deliberately conservative — generic / low-entropy
# hits stay LOW so a flood of partials doesn't drown out the
# high-confidence AWS / GCP / cloud-provider keys an operator
# actually needs to rotate this afternoon.
#
# Phase 3 cleanup item #8: pre-cleanup, ``("jwt",)`` /
# ``("oauth",)`` / ``("api-key",)`` lacked the trailing-dash
# discipline of the other entries.  ``startswith("jwt")`` would
# match any rule whose name BEGAN with "jwt", including unintended
# future rules like ``jwt-anything-else-a-future-rule-might-be-named``.
# The split into exact-name + dashed-prefix tables locks the
# matching down: exact-name rules use ``==``; prefix-family rules
# require the trailing dash.
_SEVERITY_BY_RULE_PREFIX: list[tuple[tuple[str, ...], str, str]] = [
    # (rule_id prefixes — TRAILING DASH REQUIRED, secret_kind, severity)
    (
        ("aws-",),
        "AWS access key",
        "critical",
    ),
    (
        ("gcp-", "google-cloud-"),
        "GCP service-account credential",
        "critical",
    ),
    (
        ("azure-", "microsoft-"),
        "Azure / Microsoft credential",
        "critical",
    ),
    (
        ("private-key-", "rsa-private-key-", "ssh-", "pgp-"),
        "Private key material",
        "critical",
    ),
    (
        ("github-", "gitlab-", "bitbucket-"),
        "Source-host personal access token",
        "high",
    ),
    (
        ("stripe-", "twilio-", "sendgrid-", "slack-"),
        "Third-party API key (production-scope)",
        "high",
    ),
    (
        ("jwt-", "bearer-", "oauth-"),
        "Bearer / OAuth token",
        "medium",
    ),
    (
        ("api-key-", "generic-api-key-"),
        "Generic API key",
        "medium",
    ),
]

#: Gitleaks default rules whose canonical names do NOT carry a
#: trailing family suffix.  Matched with ``==`` (case-insensitive)
#: so ``jwt`` does NOT match a hypothetical future ``jwtbomb`` rule.
_SEVERITY_BY_EXACT_RULE: dict[str, tuple[str, str]] = {
    # Bare-name rules from upstream gitleaks default config.
    "jwt": ("Bearer / OAuth token", "medium"),
    "private-key": ("Private key material", "critical"),
    "rsa-private-key": ("Private key material", "critical"),
    "generic-api-key": ("Generic API key", "medium"),
}


def _classify(rule_id: str) -> tuple[str, str]:
    """Map a gitleaks ``RuleID`` to ``(secret_kind, severity)``.

    Falls back to ``("Unclassified secret", "low")`` for rules we
    don't recognise — we want unknown rules surfaced (not dropped),
    just not as high-priority alerts.
    """
    rule_lc = rule_id.lower()
    if rule_lc in _SEVERITY_BY_EXACT_RULE:
        return _SEVERITY_BY_EXACT_RULE[rule_lc]
    for prefixes, kind, severity in _SEVERITY_BY_RULE_PREFIX:
        if any(rule_lc.startswith(p) for p in prefixes):
            return kind, severity
    return "Unclassified secret", "low"


_REDACT_MIN_LEN: int = 12
"""Minimum length below which a secret is fully masked.

The preview format is ``first-4 + "****" + last-4``.  For an
8-char secret, that's ``secret[:4] + "****" + secret[-4:]`` —
slices at ``[:4]`` and ``[-4:]`` cover the FULL string, so the
redacted preview echoes back every character of the input
(just bookended by ``****``).  Same problem holds for 9 / 10 /
11 chars (75-89% of the input revealed).

12 is the smallest threshold where ``[:4] + [-4:]`` reveal
strictly fewer than 75% of the chars (8/12 = 67%).  We pick 12
as the floor; anything below collapses to ``"*" * len(secret)``
— full mask, no partial leak.

Pre-merge security review BLOCKER #2 — the original threshold
of 8 made the redacted_preview a no-op for short secrets.
"""


def _redact(secret: str) -> str:
    """Build the operator-facing preview: first-4 + ``****`` + last-4.

    Secrets shorter than :data:`_REDACT_MIN_LEN` collapse to
    all-``*`` so the preview never reveals more than half the
    input.  Gitleaks occasionally matches very short noise that
    wouldn't survive any partial preview anyway.  The fixed
    format keeps preview length bounded for the DB column
    (``String(128)`` is more than enough).
    """
    if len(secret) < _REDACT_MIN_LEN:
        return "*" * len(secret)
    return f"{secret[:4]}****{secret[-4:]}"


def _hash(secret: str) -> str:
    """SHA-256 of the raw secret for cross-scan dedup.

    One-way; cannot recover the secret from this value.  Stored on
    :attr:`CodeFinding.secret_hash`; the API never exposes it on
    the wire.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GitleaksFinding:
    """Engine-native shape (one entry from gitleaks' JSON report).

    Used between :meth:`run` and :meth:`normalize`; never persisted.
    The ``raw_secret`` field is stripped to ``""`` before the
    dataclass leaves :meth:`run` — we keep the field on the type so
    the redaction step is explicit, not implicit.
    """

    rule_id: str
    file_path: str
    line_number: int
    column_number: int | None
    commit_sha: str | None
    raw_secret: str


class GitleaksPlugin(ScannerPlugin):
    """First repo-scanner ScannerPlugin.  Detects committed secrets."""

    id = "gitleaks"
    display_name = "Gitleaks"
    supported_target_kinds: set[str] = {"repo"}
    supported_intensities: set[str] = {ScanProfile.PASSIVE.value}
    required_capabilities: set[str] = set()

    _CLONE_TIMEOUT_S: int = 60
    _SCAN_TIMEOUT_S: int = 300
    _GITLEAKS_BIN: str = "gitleaks"

    def __init__(self, gitleaks_bin: str | None = None) -> None:
        # Override path is for tests + alternative installs (e.g. a
        # pinned gitleaks under /opt/zynksec).  Production reads it
        # from $PATH inside the code-worker image.
        self._gitleaks = gitleaks_bin or self._GITLEAKS_BIN
        self._exit_stack: ExitStack | None = None
        self._handle: RepoHandle | None = None
        # Phase 3 cleanup item #9c: discover the actual gitleaks
        # version once at instantiation rather than carrying a
        # hardcoded class-attribute that drifts from the
        # Dockerfile-pinned binary.  Falls back to ``"unknown"``
        # if the ``gitleaks version`` probe fails — version-
        # detection is observability-only, never a reason to crash
        # the worker on startup.
        self.engine_version: str = self._detect_engine_version()

    # ---- contract ----
    def supports(self, target: ScanTarget) -> bool:
        if target.kind not in self.supported_target_kinds:
            return False
        # Sprint 1 is PASSIVE-only (gitleaks has no intensity dial
        # — every run is "find every secret you can").  Any other
        # profile is rejected explicitly so a SAFE_ACTIVE / AGGRESSIVE
        # value silently mapping onto the same flow doesn't lie about
        # what ran.
        return target.scan_profile.value in self.supported_intensities

    def prepare(self, target: ScanTarget) -> ScanContext:
        """Clone the repo into the per-scan temp directory.

        The :class:`ExitStack` keeps the cloner's context manager
        alive across :meth:`run` + :meth:`normalize`; :meth:`teardown`
        closes it (which deletes the working tree).
        """
        self._verify_gitleaks_available()
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
                "gitleaks.prepare.clone_failed",
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
            raise RuntimeError("GitleaksPlugin.run called before prepare")

        report_path = self._handle.path.parent / "gitleaks.json"
        cmd = [
            self._gitleaks,
            "detect",
            "--source",
            str(self._handle.path),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-banner",
            # Exit 1 on findings, exit 0 on clean — that's the
            # gitleaks default; we restate it here to make the
            # contract explicit and to dodge a future flag rename.
            "--exit-code",
            "1",
        ]

        _log.info(
            "gitleaks.run.start",
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
                # gitleaks doesn't read stdin in normal operation,
                # but ``GIT_TERMINAL_PROMPT=0`` doesn't apply here
                # (gitleaks isn't git).  Close stdin defensively so
                # nothing from the parent process can feed it.
                # Phase 3 cleanup item #3.
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"gitleaks scan timed out after {self._SCAN_TIMEOUT_S}s") from exc

        # 0 = clean, 1 = findings present.  Anything else is a real
        # failure (malformed git tree, gitleaks crash, OOM ...).
        #
        # Pre-merge security review FINDING #5: do NOT include
        # gitleaks' stderr in the user-facing exception message.
        # Some gitleaks debug paths print matched-line excerpts to
        # stderr; including ``stderr.splitlines()[-1]`` in the
        # ``RuntimeError`` would let those plaintext fragments
        # propagate into ``Scan.failure_reason`` (DB-persisted, API-
        # returned).  The exit code alone is enough for triage; full
        # stderr is logged at debug level so operators can
        # investigate without secrets touching the DB or API
        # response.
        if completed.returncode not in (0, 1):
            _log.debug(
                "gitleaks.run.stderr",
                scan_id=str(context.target.scan_id),
                exit_code=completed.returncode,
                stderr_len=len(completed.stderr or ""),
            )
            raise RuntimeError(f"gitleaks exited with code {completed.returncode}")

        if not report_path.exists():
            # Empty repo / no commits → gitleaks may not write a
            # report at all.  Treat as zero findings.
            payload: list[dict[str, Any]] = []
        else:
            with report_path.open("r", encoding="utf-8") as f:
                # Gitleaks emits JSON-array on findings, ``null`` on
                # clean.  Both decode cleanly; ``None`` collapses to
                # an empty payload below.
                raw = json.load(f) or []
            payload = list(raw) if isinstance(raw, list) else []

        _log.info(
            "gitleaks.run.done",
            scan_id=str(context.target.scan_id),
            exit_code=completed.returncode,
            findings=len(payload),
        )

        return RawScanResult(
            engine="gitleaks",
            payload={"raw_findings": payload},
        )

    def normalize(
        self,
        raw: RawScanResult,
        context: ScanContext,
    ) -> Iterator[Any]:
        """Yield engine-native :class:`GitleaksFinding` instances.

        Phase 3 Sprint 1 doesn't pass through the canonical
        :class:`zynksec_schema.Finding` (HTTP-shaped, doesn't fit);
        the worker calls :func:`code_findings_from_gitleaks` to map
        these to :class:`zynksec_db.CodeFinding` rows directly.

        This yields ``Any`` to satisfy the abstract signature; the
        worker dispatcher knows ``plugin.id == "gitleaks"`` means
        the iterator carries ``GitleaksFinding`` objects, not
        ``Finding`` ones.
        """
        del context  # gitleaks output is self-contained; no context fixup
        for entry in raw.payload.get("raw_findings", []):
            try:
                rule_id = str(entry["RuleID"])
                file_path = str(entry["File"])
                line_number = int(entry.get("StartLine") or 0)
                column_number_value = entry.get("StartColumn")
                column_number = (
                    int(column_number_value) if column_number_value is not None else None
                )
                commit_sha = entry.get("Commit") or None
                raw_secret = str(entry.get("Secret") or "")
            except (KeyError, TypeError, ValueError) as exc:
                _log.warning(
                    "gitleaks.normalize.skipped_malformed_entry",
                    error=str(exc),
                )
                continue

            if not raw_secret or not file_path or not rule_id:
                # Without a raw match value we can't redact + hash;
                # without a file path the finding has nowhere to
                # point.  Drop the entry (very rare in practice).
                continue

            yield GitleaksFinding(
                rule_id=rule_id,
                file_path=file_path,
                line_number=line_number,
                column_number=column_number,
                commit_sha=commit_sha,
                raw_secret=raw_secret,
            )

    def teardown(self, context: ScanContext) -> None:
        """Close the cloner context manager — deletes the working tree.

        Best-effort.  A teardown failure is logged but never
        re-raised; an otherwise-successful scan must not be marked
        failed because the rmtree blipped.
        """
        del context  # path lives on the handle / exit stack
        if self._exit_stack is not None:
            try:
                self._exit_stack.close()
            except Exception as exc:  # noqa: BLE001 — best-effort
                _log.warning("gitleaks.teardown.failed", error=str(exc))
            finally:
                self._exit_stack = None
                self._handle = None

    def health_check(self) -> HealthStatus:
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._gitleaks, "version"],
                check=False,
                timeout=10,
                capture_output=True,
                text=True,
                # Same rationale as the ``run`` site above —
                # defence in depth (Phase 3 cleanup item #3).
                stdin=subprocess.DEVNULL,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return HealthStatus(ok=False, message=f"gitleaks unavailable: {exc}")
        if completed.returncode != 0:
            return HealthStatus(ok=False, message=(completed.stderr or "").strip()[:200])
        version = (completed.stdout or "").strip() or None
        return HealthStatus(ok=True, engine_version=version)

    # ---- helpers ----
    def _verify_gitleaks_available(self) -> None:
        """Fail fast in :meth:`prepare` if the binary isn't on PATH."""
        if shutil.which(self._gitleaks) is None:
            raise RuntimeError(
                f"gitleaks binary {self._gitleaks!r} not on PATH; "
                "is the code-worker image built from "
                "infra/docker/code-worker.Dockerfile?",
            )

    def _detect_engine_version(self) -> str:
        """Run ``gitleaks version`` once and return the parsed string.

        Observability-only: the value is cached on the instance and
        echoed in ``ScanContext.metadata['engine_version']`` so log
        readers can see which gitleaks binary actually ran.  Any
        failure (binary missing, subprocess crash, weird output)
        falls back to ``"unknown"`` rather than raising — the
        worker should still be able to scan even if version
        detection blips.
        """
        if shutil.which(self._gitleaks) is None:
            return "unknown"
        try:
            completed = subprocess.run(  # noqa: S603 — list-form, fixed args
                [self._gitleaks, "version"],
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


def code_findings_from_gitleaks(
    findings: Iterable[GitleaksFinding],
    *,
    scan_id: uuid.UUID,
) -> list[dict[str, Any]]:
    """Map gitleaks engine-native findings to ``CodeFinding`` row kwargs.

    Helper rather than a method so the worker can construct the
    SQLAlchemy rows in one place (where it owns the session) and
    the plugin stays free of DB imports.

    The returned dicts go straight into ``CodeFinding(**row)`` —
    no plaintext secret, just the redacted preview + hash.
    """
    rows: list[dict[str, Any]] = []
    for f in findings:
        kind, severity = _classify(f.rule_id)
        rows.append(
            {
                "scan_id": scan_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "column_number": f.column_number,
                "rule_id": f.rule_id,
                "secret_kind": kind,
                "severity": severity,
                "redacted_preview": _redact(f.raw_secret),
                "secret_hash": _hash(f.raw_secret),
                "commit_sha": f.commit_sha,
            },
        )
    return rows
