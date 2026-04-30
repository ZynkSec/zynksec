"""Phase 3 Sprint 3 — OsvScannerPlugin end-to-end.

CLAUDE.md §7 — real Postgres, real Redis, real Celery, real
osv-scanner binary inside the code-worker, real bare repo served
by the gitfixture (carrying the lockfile plant under
``osv-plants/`` alongside the gitleaks + Semgrep plants).  No
mocks.

The OSV scanner queries ``api.osv.dev`` over HTTPS for every
package surfaced by the lockfile walk.  The test runner needs
outbound network — the only flaky-ish dependency in the suite,
documented in ``packages/scanners/.../osv/__init__.py``.

Coverage:
  * ``test_osv_scan_finds_lockfile_vulnerabilities`` — POST a
    kind=repo scan with ``scanner="osv-scanner"`` against the
    fixture; assert ``code_findings`` carries at least one row
    for the planted ``lodash@4.17.20`` advisory cluster, with
    rule_id == ``GHSA-35jh-r3h4-6jhm`` (the high-severity
    command-injection / CVE-2021-23337) present.
  * ``test_osv_scan_severity_mapping`` — assert the planted
    high-severity rule lands as ``severity="high"`` (not the raw
    CVSS score, not raw OSV severity strings).
  * ``test_osv_scan_redacted_preview_format`` — assert the
    persisted ``redacted_preview`` matches the canonical
    ``<pkg>@<ver> → <fix>`` shape; specifically pin the lodash
    plant's ``lodash@4.17.20 → 4.17.21`` since both fixed
    advisories share the 4.17.21 fix.

The Sprint 1 / 2 default-still-gitleaks contract is already
covered by ``test_repo_scan_default_scanner_is_gitleaks`` in
``test_semgrep_scan.py`` — no point duplicating it here.
"""

from __future__ import annotations

import re
import time
import uuid

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import CodeFinding

_TERMINAL_POLL_INTERVAL_S = 1.0
# osv-scanner spends most of its wall time on api.osv.dev round-trips
# (one batched query per package).  300 s keeps the test diagnostic
# without hiding a real regression — typical run on the fixture is
# 5-15 s once cached.
_TERMINAL_BUDGET_S = 300.0

_FIXTURE_REPO_URL = "http://gitfixture/vulnerable-repo.git"

# Plant identity — see ``tests/fixtures/osv-plants/README.md``.
_PLANTED_ADVISORY = "GHSA-35jh-r3h4-6jhm"  # CVE-2021-23337, CVSS 7.2 / high
_PLANTED_PACKAGE = "lodash"
_PLANTED_VERSION = "4.17.20"
_PLANTED_FIX = "4.17.21"
_PLANTED_LOCKFILE = "osv-plants/package-lock.json"

# Redacted-preview canonical shape: ``<pkg>@<ver> → <fix>``.
# Whitespace + arrow are part of the contract — operators read
# this directly in dashboards.
_PREVIEW_PATTERN = re.compile(r"^[^@\s]+@[^\s]+ → (?:[^\s]+|no fix)$")


def _wait_for_terminal(client: httpx.Client, scan_id: str) -> dict:
    deadline = time.monotonic() + _TERMINAL_BUDGET_S
    last: dict = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200, response.text
        last = response.json()
        if last["status"] in ("completed", "failed"):
            return last
        time.sleep(_TERMINAL_POLL_INTERVAL_S)
    raise AssertionError(
        f"scan {scan_id} did not terminate within {_TERMINAL_BUDGET_S}s; last={last}",
    )


def _post_repo_target(client: httpx.Client, *, name: str | None = None) -> dict:
    body = {
        "name": name or f"vuln-repo-{uuid.uuid4().hex[:8]}",
        "url": _FIXTURE_REPO_URL,
        "kind": "repo",
    }
    response = client.post("/api/v1/targets", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _enqueue_osv_scan(client: httpx.Client) -> str:
    target = _post_repo_target(client)
    response = client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "osv-scanner"},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def test_osv_scan_finds_lockfile_vulnerabilities(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """End-to-end: clone, osv-scanner --recursive, persist, surface.

    Floor assertion (``count >= 1`` for the planted GHSA) rather
    than equality — OSV's advisory database grows over time and
    additional lodash@4.17.20 rules may appear later (snapshot
    2026-04-29: 5 distinct advisories).  Pinning the count would
    create a false-flake every time upstream publishes a new
    advisory.  The contract is "the high-severity plant is
    detected"; surfacing more is operationally fine.
    """
    scan_id = _enqueue_osv_scan(api_client)
    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body
    # API surfaces the resolved scanner name on the response.
    assert body["scanner"] == "osv-scanner", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    assert rows, "OSV scan against lodash@4.17.20 produced zero CodeFinding rows"

    # OSV findings are package-shaped — line_number / column_number
    # / commit_sha / secret_hash / secret_kind all NULL (per
    # migration 0009 + the plugin's normalize() contract).
    for r in rows:
        assert r.line_number is None, r
        assert r.column_number is None, r
        assert r.commit_sha is None, r
        assert r.secret_hash is None, r
        assert r.secret_kind is None, r
        # file_path points at the lockfile, not arbitrary source.
        assert r.file_path == _PLANTED_LOCKFILE, r

    # The planted high-severity GHSA must be present.
    planted = [r for r in rows if r.rule_id == _PLANTED_ADVISORY]
    assert planted, (
        f"planted advisory {_PLANTED_ADVISORY!r} missing from OSV scan; "
        f"got rule_ids {sorted({r.rule_id for r in rows})}"
    )

    # Surface on the API too — code_findings populated, findings empty.
    assert len(body["code_findings"]) >= 1, body["code_findings"]
    assert body["findings"] == [], body["findings"]


def test_osv_scan_severity_mapping(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Persisted severity values are zynksec enum (low/medium/high/critical),
    not raw CVSS scores or OSV severity strings.

    The planted CVE-2021-23337 carries CVSS 7.2 → ``high`` per
    NIST cut-offs; this test pins that mapping.  A future change
    that moved the boundary or stopped reading
    ``groups[].max_severity`` would surface here.
    """
    scan_id = _enqueue_osv_scan(api_client)
    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    valid_severities = {"low", "medium", "high", "critical"}
    for r in rows:
        assert r.severity in valid_severities, f"row severity {r.severity!r} not in zynksec enum"

    planted = [r for r in rows if r.rule_id == _PLANTED_ADVISORY]
    assert planted, "planted high-severity GHSA missing"
    assert planted[0].severity == "high", (
        f"{_PLANTED_ADVISORY} (CVSS 7.2) should map to 'high', got " f"{planted[0].severity!r}"
    )


def test_osv_scan_redacted_preview_format(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Every persisted ``redacted_preview`` matches ``<pkg>@<ver> → <fix>``.

    The planted lodash@4.17.20 row pins the canonical fixed-version
    case; rows for other (unrelated) advisories may show ``no fix``
    as the right-hand side, so the assertion uses a regex that
    allows either.

    Operators read these previews directly in dashboards, so the
    arrow + spacing is part of the public contract — not just an
    implementation detail.
    """
    scan_id = _enqueue_osv_scan(api_client)
    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    assert rows, "no OSV findings to inspect"

    for r in rows:
        assert _PREVIEW_PATTERN.match(r.redacted_preview), (
            f"preview {r.redacted_preview!r} does not match " f"<pkg>@<ver> → <fix>"
        )

    # Pin the planted lodash row's preview shape exactly — both
    # template-related lodash@4.17.20 advisories fix in 4.17.21,
    # so this string is stable across runs.
    planted = [r for r in rows if r.rule_id == _PLANTED_ADVISORY]
    assert planted, "planted GHSA missing"
    assert (
        planted[0].redacted_preview == f"{_PLANTED_PACKAGE}@{_PLANTED_VERSION} → {_PLANTED_FIX}"
    ), planted[0].redacted_preview
