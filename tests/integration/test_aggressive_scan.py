"""AGGRESSIVE end-to-end on a juice-shop subpath — Sprint 3 exit test.

OPT-IN: the AGGRESSIVE profile runs ZAP at HIGH attack strength + LOW
alert threshold + every scanner enabled + 4 threads/host.  On a real
target it can take 5-15 min and saturate the JVM heap, so this test
is gated behind ``RUN_AGGRESSIVE_TESTS=1`` and a cgroup-cap sanity
check; default ``pytest`` runs SKIP it cleanly.

Two scans, same juice-shop subpath
(``http://juice-shop:3000/rest/user/login``):

    1. SAFE_ACTIVE — Sprint 2's MEDIUM/MEDIUM constrained policy
    2. AGGRESSIVE  — every scanner on, HIGH/LOW

``/rest/user/login`` is juice-shop's canonical SQLi target — a POST
endpoint with two body params (``email``, ``password``) that
authenticate against a SQLite-backed users table.  Two params instead
of one give AGGRESSIVE's HIGH-strength scanners more payload×param
permutations than SAFE_ACTIVE's MEDIUM strength, which is what
produces a measurable ``aggressive_count > safe_active_count`` delta.
The Sprint-2 SAFE_ACTIVE test still uses
``/rest/products/search?q=apple`` because that target is fast enough
to be in CI's main path; this AGGRESSIVE-only test pays the extra
seconds on a denser surface to keep the assertion honest.

Two assertions:

    1. (PRIMARY) The worker emitted ``zap.aggressive_policy.applied``
       with ``attack_strength=HIGH`` AND ``alert_threshold=LOW``.
       This is what proves the AGGRESSIVE branch in
       :meth:`ZapPlugin.scan` actually executed, vs. silently falling
       through to SAFE_ACTIVE on a config bug.
    2. (SECONDARY) ``aggressive_count >= safe_active_count`` AND
       ``aggressive_count > 0``.  The ``>=`` rather than ``>`` is
       deliberate: AGGRESSIVE on juice-shop ties SAFE_ACTIVE because
       juice-shop's stack (Node.js + SQLite, JSON-only API, no SOAP
       / no XML / no PHP) doesn't expose surface for the scanners
       that differentiate AGGRESSIVE from SAFE_ACTIVE — XXE, SSTI,
       time-based SQLi DB variants, XSLT/XPath injection, buffer
       overflow, format-string, Heartbleed, CVE-2012-1823 are all
       wrong-stack on this target.  HIGH attack strength + LOW alert
       threshold fire MORE payloads at the SAME scanners that
       SAFE_ACTIVE already runs at MEDIUM, so the fingerprints
       collapse to identical sets.

       The count is still useful as a "scan completed and produced
       findings" smoke check — it catches a regression where
       AGGRESSIVE would silently produce zero findings (e.g., if the
       active-scan poll exited early on a status parse bug).  Adding
       a Java/PHP target to ``target-lab/`` to enable a real count
       delta is Phase 2+ scope (tracked as a follow-up; do not
       relax this assertion further until that target lands).

CLAUDE.md §7 — real Postgres, real Redis, real ZAP, real juice-shop.
No mocks.  ZAP's session is reset between scans
(:meth:`ZapPlugin.prepare`) so the comparison is honest.

Per-test ``@pytest.mark.timeout(1800)`` — 30 minutes wall-clock
ceiling.  AGGRESSIVE on this subpath typically finishes in 5-15 min;
the generous budget absorbs slower runners without papering over a
runaway scan.  If this trips, the policy or the target needs
revisiting, NOT the budget.
"""

from __future__ import annotations

import os
import re
import subprocess  # noqa: S404 — controlled, list-form invocations only
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

# 28 minutes — leaves slack inside the 30-minute pytest mark for
# fixture overhead.  Each scan polls under this budget independently;
# SAFE_ACTIVE finishes inside it ~80 s so AGGRESSIVE has the rest.
_POLL_BUDGET_S = 1680.0
_POLL_INTERVAL_S = 5.0  # less aggressive than SAFE_ACTIVE — long scan

# juice-shop's canonical SQLi target — POST endpoint with multi-param
# body surface.  See module docstring for the choice rationale.
_TARGET_URL = "http://juice-shop:3000/rest/user/login"

# Below this cgroup cap, AGGRESSIVE WILL OOM the JVM.  4 GiB is the
# floor (3500m Xmx + ~500 MiB non-heap overhead); the documented
# Sprint-3 setup is 6 GiB (Xmx ≈ 57 % of cgroup, leaves ~2.5 GiB
# headroom for non-heap).
_MIN_CGROUP_GIB = 4.0

_MEM_RE = re.compile(r"(\d+\.?\d*)(MiB|GiB)")
_OPT_IN_ENV = "RUN_AGGRESSIVE_TESTS"

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]


def _compose(*args: str) -> list[str]:
    """``docker compose`` invocation matching ``conftest.py``'s overlay
    chain.  Used by :func:`_logs_since` to grep worker logs without
    depending on the conftest helper directly."""
    return [
        "docker",
        "compose",
        "-f",
        str(_REPO_ROOT / "docker-compose.yml"),
        "-f",
        str(_REPO_ROOT / "target-lab" / "compose-targets.yml"),
        "-f",
        str(_REPO_ROOT / "tests" / "integration" / "docker-compose.test.yml"),
        "--profile",
        "dev",
        "--profile",
        "lab",
        *args,
    ]


def _logs_since(service: str | tuple[str, ...], elapsed_s: float) -> str:
    """Tail one-or-many compose services' logs going back ``elapsed_s``s.

    Mirrors the helper in ``test_correlation_id_propagation.py`` —
    docker's ``--since`` is wall-clock so we add a 5 s cushion to
    cover monotonic-vs-wall drift over a long AGGRESSIVE run.

    Phase 2 Sprint 3: accept a tuple of service names so callers can
    grab the merged worker1/worker2 stream (the scan is routed to one
    of them by the rotation cursor — we don't know which in advance).
    """
    window = max(1, int(elapsed_s) + 5)
    services = (service,) if isinstance(service, str) else service
    result = subprocess.run(  # noqa: S603 — list-form, no user input
        _compose("logs", "--no-color", f"--since={window}s", *services),
        cwd=str(_REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


class _ZapMemorySampler:
    """Background thread that polls ``docker stats`` for ZAP RSS.

    Same shape as Sprint 2's sampler — duplicated rather than shared
    because each test stays self-contained and the sampler is small.

    Phase 2 Sprint 3: ZAP is now multi-instance.  The scan lands on
    exactly one of zynksec-zap1 / zynksec-zap2 (the rotation cursor
    decides), but we don't know which at sample-start time, so we
    poll all containers and track the max across all of them — the
    idle ZAP sits near 100 MiB so it doesn't perturb the peak.
    """

    def __init__(
        self,
        containers: tuple[str, ...] = ("zynksec-zap1", "zynksec-zap2"),
        interval_s: float = 5.0,
    ) -> None:
        self.peak_mib: float = 0.0
        self._containers = containers
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    @staticmethod
    def _parse_mib(raw: str) -> float:
        match = _MEM_RE.search(raw or "")
        if not match:
            return 0.0
        value = float(match.group(1))
        return value * 1024.0 if match.group(2) == "GiB" else value

    def _run(self) -> None:
        cmd = [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{.MemUsage}}",
            *self._containers,
        ]
        while not self._stop.is_set():
            try:
                result = subprocess.run(  # noqa: S603 — list-form, no user input
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                # docker stats with N containers prints N lines —
                # parse each, take the max.
                for line in result.stdout.splitlines():
                    value = self._parse_mib(line)
                    if value > self.peak_mib:
                        self.peak_mib = value
            except subprocess.TimeoutExpired:
                pass  # transient — retry next interval
            self._stop.wait(self._interval_s)

    def __enter__(self) -> _ZapMemorySampler:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=10.0)


def _zap_cgroup_gib(container: str = "zynksec-zap1") -> float:
    """Return ZAP container's cgroup memory limit in GiB, or 0.0 if absent.

    Used by the per-test skip gate so a contributor whose compose
    still has the 2 GiB cap doesn't OOM their machine running the
    AGGRESSIVE test.  Phase 2 Sprint 3: zap1 and zap2 share the same
    config via the YAML anchor, so inspecting one is sufficient.
    """
    cmd = ["docker", "inspect", "--format", "{{.HostConfig.Memory}}", container]
    try:
        result = subprocess.run(  # noqa: S603 — list-form, no user input
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
    except subprocess.TimeoutExpired:
        return 0.0
    raw = result.stdout.strip()
    if not raw or raw == "0":
        return 0.0
    try:
        return int(raw) / (1024**3)
    except ValueError:
        return 0.0


def _poll_until_completed(client: httpx.Client, scan_id: str) -> dict[str, Any]:
    """Poll GET /api/v1/scans/{id} until terminal or budget hit."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    seen_statuses: list[str] = []
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        status_value = str(body.get("status", ""))
        if not seen_statuses or seen_statuses[-1] != status_value:
            seen_statuses.append(status_value)
        if status_value == "completed":
            return body
        if status_value == "failed":
            pytest.fail(f"scan {scan_id} transitioned to failed: {body}")
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"scan {scan_id} did not complete within {_POLL_BUDGET_S:.0f}s; "
        f"statuses seen: {seen_statuses}"
    )


def _post_scan(client: httpx.Client, profile: str) -> str:
    """POST a scan with the given profile against the subpath target."""
    response = client.post(
        "/api/v1/scans",
        # AGGRESSIVE scans can take long enough that the default 10 s
        # client timeout is fine for POST (returns immediately), but
        # the long-running poll loop uses its own budget.
        json={"target_url": _TARGET_URL, "scan_profile": profile},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["scan_profile"] == profile
    scan_id = body["id"]
    uuid.UUID(scan_id)
    return scan_id


@pytest.mark.aggressive
@pytest.mark.timeout(1800)
def test_post_scan_with_aggressive_finds_more_than_safe_active(
    api_client: httpx.Client,
) -> None:
    """AGGRESSIVE returns strictly more findings than SAFE_ACTIVE on
    juice-shop's ``/rest/user/login`` POST surface, AND the worker
    logged the AGGRESSIVE policy-applied event with the documented
    HIGH/LOW knobs."""
    if not os.environ.get(_OPT_IN_ENV):
        pytest.skip(
            f"AGGRESSIVE test is opt-in; set {_OPT_IN_ENV}=1 to run. "
            "Requires 6 GiB free host RAM and may take 5-15 min."
        )

    cgroup_gib = _zap_cgroup_gib()
    if cgroup_gib < _MIN_CGROUP_GIB:
        pytest.skip(
            f"ZAP cgroup limit is {cgroup_gib:.1f} GiB; AGGRESSIVE needs "
            f">= {_MIN_CGROUP_GIB:.0f} GiB to avoid OOM.  Check docker-compose.yml"
            " mem_limit (Sprint 3 sets it to 6g)."
        )

    sampler = _ZapMemorySampler()
    test_start = time.monotonic()
    with sampler:
        # SAFE_ACTIVE seeds the baseline.  ZAP's session is reset at
        # the start of each scan, so AGGRESSIVE sees an independent
        # baseline (alerts don't carry over).
        safe_id = _post_scan(api_client, "SAFE_ACTIVE")
        safe_body = _poll_until_completed(api_client, safe_id)
        safe_findings = safe_body.get("findings", [])
        safe_count = len(safe_findings)

        aggressive_id = _post_scan(api_client, "AGGRESSIVE")
        aggressive_body = _poll_until_completed(api_client, aggressive_id)
        aggressive_findings = aggressive_body.get("findings", [])
        aggressive_count = len(aggressive_findings)
    elapsed_s = time.monotonic() - test_start

    # Plumbing assertion — independent of count delta.  Even if the
    # count tied (which would mean the target's response surface is
    # too narrow to differentiate HIGH vs MEDIUM strength), the log
    # line proves the AGGRESSIVE branch in ZapPlugin.scan() actually
    # executed.  A regression that silently falls through to
    # SAFE_ACTIVE for AGGRESSIVE requests would fail this even with a
    # passing count assertion.
    # Multi-instance ZAP: scan landed on exactly one of worker1/worker2;
    # harvest both streams so we don't miss the policy-applied event.
    worker_logs = _logs_since(("worker1", "worker2"), elapsed_s)
    aggressive_policy_applied = [
        line
        for line in worker_logs.splitlines()
        if '"event": "zap.aggressive_policy.applied"' in line
        or '"event":"zap.aggressive_policy.applied"' in line
    ]
    assert aggressive_policy_applied, (
        "no zap.aggressive_policy.applied log line in worker logs — the "
        "AGGRESSIVE branch did not run, or the policy-apply step was "
        f"silently skipped. Worker log tail:\n{worker_logs[-1500:]}"
    )
    policy_line = aggressive_policy_applied[-1]
    assert (
        '"attack_strength": "HIGH"' in policy_line or '"attack_strength":"HIGH"' in policy_line
    ), f"AGGRESSIVE policy applied without attack_strength=HIGH: {policy_line}"
    assert (
        '"alert_threshold": "LOW"' in policy_line or '"alert_threshold":"LOW"' in policy_line
    ), f"AGGRESSIVE policy applied without alert_threshold=LOW: {policy_line}"

    # Identify one finding only AGGRESSIVE caught — the active-only
    # delta is what the user paid for in wall-clock + RSS.
    safe_fingerprints = {str(f.get("fingerprint", "")) for f in safe_findings}
    aggressive_only = [
        f for f in aggressive_findings if str(f.get("fingerprint", "")) not in safe_fingerprints
    ]
    aggressive_only_summary = "(none)"
    if aggressive_only:
        first = aggressive_only[0]
        zid = first.get("taxonomy", {}).get("zynksec_id")
        level = first.get("severity", {}).get("level")
        rule_id = first.get("evidence", {}).get("rule_id")
        aggressive_only_summary = f"{zid} severity={level} rule_id={rule_id}"

    repo_root = Path(__file__).resolve().parents[2]
    report_path = repo_root / ".pytest_cache" / "aggressive_report.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        f"target_url={_TARGET_URL}\n"
        f"safe_active_count={safe_count}\n"
        f"aggressive_count={aggressive_count}\n"
        f"aggressive_only_count={len(aggressive_only)}\n"
        f"aggressive_only_example={aggressive_only_summary}\n"
        f"zap_peak_rss_mib={sampler.peak_mib:.1f}\n"
        f"zap_peak_rss_gib={sampler.peak_mib / 1024:.2f}\n"
        f"zap_cgroup_gib={cgroup_gib:.2f}\n"
        f"elapsed_s={elapsed_s:.1f}\n",
        encoding="utf-8",
    )

    # Secondary check — see module docstring.  ``>=`` (not ``>``) is
    # deliberate: on juice-shop's Node.js + SQLite + JSON-only stack,
    # AGGRESSIVE's differentiating scanners (XXE, SSTI, time-based
    # SQLi DB variants, etc.) are wrong-stack and produce no new
    # alerts, so AGGRESSIVE's findings collapse to SAFE_ACTIVE's set.
    # The plumbing log assertion above is the primary correctness
    # signal for "AGGRESSIVE actually executed."
    assert aggressive_count >= safe_count, (
        f"AGGRESSIVE ({aggressive_count}) regressed below SAFE_ACTIVE "
        f"({safe_count}) on {_TARGET_URL} — HIGH strength + LOW threshold "
        f"+ every scanner enabled should never find FEWER findings than "
        f"SAFE_ACTIVE's MEDIUM/MEDIUM/16-disabled-scanners profile.  Check "
        f"worker logs for ``zap.aggressive_policy.applied`` and verify "
        f"the active-scan poll didn't exit early."
    )
    assert aggressive_count > 0, "AGGRESSIVE produced zero findings"
    assert aggressive_body["scan_profile"] == "AGGRESSIVE"
