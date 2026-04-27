"""SAFE_ACTIVE end-to-end on a juice-shop subpath — Sprint 2 exit test.

Two scans, same juice-shop endpoint:

    1. PASSIVE     — spider + passive analysers only
    2. SAFE_ACTIVE — spider + passive + ``zynksec_safe`` active scan

The target is ``http://juice-shop:3000/rest/products/search?q=apple``
rather than ``/`` (the full juice-shop site).  Why a subpath:

    Scanning the full juice-shop site at MEDIUM attack strength
    exceeds the CI active-scan budget — the active phase reaches only
    ~32-52% of progress in 10 minutes (depending on strength) because
    of juice-shop's pathologically dense parameter surface.  A subpath
    preserves the plugin invariant we want to assert
    (SAFE_ACTIVE > PASSIVE) while finishing inside a ~5-minute budget.

    ``/rest/products/search?q=apple`` is the classic juice-shop SQLi
    entry point — it's a dynamic Express route that takes the ``q``
    query parameter directly into a database call, so the active scan
    lights up SQL-injection plus reflected/persistent XSS scanners
    against the response body.  Empirically gives 1-3 net-new findings
    over PASSIVE.

    Manual full-target verification stays in the README's release
    checklist as a recommended pre-tag gate (docs/04 §0.20).

CLAUDE.md §7 — real Postgres, real Redis, real ZAP, real juice-shop.
No mocks.  ZAP's session is reset in :meth:`ZapPlugin.prepare` so the
two scans see independent baselines (without that, alerts accumulate
across scans for the daemon's lifetime and the comparison is
dishonest).

The 8-minute ``@pytest.mark.timeout(480)`` is the wall-clock ceiling
for this test on a subpath target — generous enough for the
~5-minute typical run plus ZAP idle GC plus fixture overhead.  If
it trips, either juice-shop is over-saturated or the policy regressed
— investigate, do NOT extend the budget.
"""

from __future__ import annotations

import re
import subprocess  # noqa: S404 — controlled, list-form invocations only
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

# 7 minutes — leaves a minute of slack inside the 8-minute pytest mark.
_POLL_BUDGET_S = 420.0
_POLL_INTERVAL_S = 2.0

# juice-shop subpath — see module docstring for selection rationale.
_TARGET_URL = "http://juice-shop:3000/rest/products/search?q=apple"

_MEM_RE = re.compile(r"(\d+\.?\d*)(MiB|GiB)")


class _ZapMemorySampler:
    """Background thread that polls ``docker stats`` for ZAP RSS.

    Runs ``docker stats --no-stream`` every 2 s during the scan and
    tracks the peak ``MemUsage`` reading.  Cheap (subprocess + parse;
    no docker SDK dependency) and good enough for "did SAFE_ACTIVE
    push us close to the 2 GiB cap" forensics in the paste-back report.
    """

    def __init__(self, container: str = "zynksec-zap", interval_s: float = 2.0) -> None:
        self.peak_mib: float = 0.0
        self._container = container
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
        # Extracted to a variable so ruff S607 doesn't see a literal
        # ``"docker"`` and conclude we're invoking a partial path —
        # same pattern conftest.py uses for its compose helpers.
        cmd = [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{.MemUsage}}",
            self._container,
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
                value = self._parse_mib(result.stdout)
                if value > self.peak_mib:
                    self.peak_mib = value
            except subprocess.TimeoutExpired:
                pass  # transient slow stats call, just retry
            self._stop.wait(self._interval_s)

    def __enter__(self) -> _ZapMemorySampler:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)


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
        json={"target_url": _TARGET_URL, "scan_profile": profile},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["scan_profile"] == profile
    scan_id = body["id"]
    uuid.UUID(scan_id)
    return scan_id


@pytest.mark.timeout(480)
def test_post_scan_with_safe_active_completes_and_finds_more_than_passive(
    api_client: httpx.Client,
) -> None:
    """SAFE_ACTIVE returns strictly more findings than PASSIVE on the
    juice-shop SQLi-vulnerable subpath.  Peak ZAP RSS + finding counts
    + a representative SAFE-only finding are written to
    ``.pytest_cache/safe_active_report.txt`` so the values survive even
    if pytest's capture mode swallows stdout."""
    sampler = _ZapMemorySampler()
    with sampler:
        # PASSIVE seeds the baseline.  ZAP's session is reset at the
        # start of each scan (ZapPlugin.prepare → core/action/newSession),
        # so the SAFE_ACTIVE run sees an independent baseline.
        passive_id = _post_scan(api_client, "PASSIVE")
        passive_body = _poll_until_completed(api_client, passive_id)
        passive_findings = passive_body.get("findings", [])
        passive_count = len(passive_findings)

        safe_active_id = _post_scan(api_client, "SAFE_ACTIVE")
        safe_active_body = _poll_until_completed(api_client, safe_active_id)
        safe_active_findings = safe_active_body.get("findings", [])
        safe_active_count = len(safe_active_findings)

    # Identify one finding only SAFE_ACTIVE caught — the active-only
    # delta is the entire point of this profile.
    passive_fingerprints = {str(f.get("fingerprint", "")) for f in passive_findings}
    safe_only = [
        f for f in safe_active_findings if str(f.get("fingerprint", "")) not in passive_fingerprints
    ]
    safe_only_summary = "(none)"
    if safe_only:
        first = safe_only[0]
        zid = first.get("taxonomy", {}).get("zynksec_id")
        level = first.get("severity", {}).get("level")
        rule_id = first.get("evidence", {}).get("rule_id")
        safe_only_summary = f"{zid} severity={level} rule_id={rule_id}"

    # Write to a stable repo-relative path so the run script + paste-
    # back report can grep without spelunking pytest's tmp tree.
    repo_root = Path(__file__).resolve().parents[2]
    report_path = repo_root / ".pytest_cache" / "safe_active_report.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        f"target_url={_TARGET_URL}\n"
        f"passive_count={passive_count}\n"
        f"safe_active_count={safe_active_count}\n"
        f"safe_only_count={len(safe_only)}\n"
        f"safe_only_example={safe_only_summary}\n"
        f"zap_peak_rss_mib={sampler.peak_mib:.1f}\n"
        f"zap_peak_rss_gib={sampler.peak_mib / 1024:.2f}\n",
        encoding="utf-8",
    )

    # The whole point of SAFE_ACTIVE: it must add findings on top of
    # what PASSIVE detects.  Equal counts mean the active scan ran but
    # found nothing new (policy too restrictive) or didn't run at all.
    assert safe_active_count > passive_count, (
        f"SAFE_ACTIVE ({safe_active_count}) did not exceed PASSIVE "
        f"({passive_count}) on {_TARGET_URL}.  Policy may be over-restricted "
        f"or the subpath target is too thin — pick a denser subpath, do "
        f"NOT disable more scanners."
    )
    assert safe_active_count > 0, "SAFE_ACTIVE produced zero findings"
    assert safe_active_body["scan_profile"] == "SAFE_ACTIVE"
