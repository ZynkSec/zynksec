"""Phase 3 Sprint 4 — TrivyPlugin end-to-end (IaC misconfig mode).

CLAUDE.md §7 — real Postgres, real Redis, real Celery, real
trivy binary inside the code-worker, real bare repo served by
the gitfixture (carrying the IaC plants under ``iac-plants/``
alongside the gitleaks + Semgrep + OSV plants from previous
sprints).  No mocks.

OFFLINE BY DESIGN.  ``--skip-policy-update --skip-db-update
--offline-scan`` flags ensure the scanner makes NO outbound
network calls at scan time.  This is asserted at the unit-test
level (``tests/unit/test_trivy_classify.py::
test_offline_flags_present_in_argv``) AND end-to-end here by
running the scan in the integration stack — Trivy would block
on a policy-update HTTP call otherwise, so a successful scan
in this stack proves the offline path works through the real
worker subprocess wiring.

Coverage:
  * ``test_trivy_scan_finds_iac_misconfigurations`` — POST a
    kind=repo scan with ``scanner="trivy"`` against the fixture;
    assert ``code_findings`` carries rows for the planted
    DS-0001 / DS-0002 / DS-0026 (Dockerfile) and KSV-0017
    (privileged Pod) rules with ``file_path`` pointing at the
    correct plant.
  * ``test_trivy_scan_severity_mapping`` — assert severity values
    are the lowercased canonical enum (low/medium/high/critical),
    not Trivy's upper-case strings.  Pin DS-0002 → high.
  * ``test_trivy_scan_persists_null_line_for_no_healthcheck`` —
    DS-0026 fires on the *absence* of a directive, so Trivy
    has no StartLine to point at.  Assert the persisted row's
    ``line_number`` is NULL — exercising migration 0009's
    nullable column end-to-end through the Trivy path.
  * ``test_unknown_scanner_lists_all_four`` — POST with
    ``scanner="bogus"``; assert 422 ``unknown_scanner`` with
    ``details.available`` containing all four scanner names.

The Sprint 1/2/3 default-still-gitleaks contract is already
covered by ``test_repo_scan_default_scanner_is_gitleaks`` in
``test_semgrep_scan.py`` — no point duplicating it here.

Imports are deliberately limited to ``zynksec_db`` (the only
worker-side package the host pytest venv has installed); the
``zynksec_scanners`` family runs inside the code-worker
container, not on the test runner — so the OFFLINE_FLAGS
invariant is validated at the unit level only.
"""

from __future__ import annotations

import time
import uuid

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import CodeFinding

_TERMINAL_POLL_INTERVAL_S = 1.0
# Trivy misconfig scans are CPU-bound on the policy engine; no
# network and no DB queries.  The fixture's tiny IaC plants
# typically finish in well under 5 seconds.  120 s is a generous
# safety cap matching the gitleaks suite's budget.
_TERMINAL_BUDGET_S = 120.0

_FIXTURE_REPO_URL = "http://gitfixture/vulnerable-repo.git"

# Plant identity — see ``tests/fixtures/iac-plants/README.md``.
# Trivy 0.70+ uses dashed rule IDs (``DS-0001``, NOT ``DS001``);
# pin the dashed form so a future Trivy bump that re-renames
# rules surfaces here.
_PLANTED_DOCKERFILE = "iac-plants/Dockerfile.bad"
_PLANTED_POD = "iac-plants/pod.yaml"
_PLANT_LATEST_TAG = "DS-0001"  # MEDIUM, on FROM ubuntu:latest
_PLANT_ROOT_USER = "DS-0002"  # HIGH, on USER root
_PLANT_NO_HEALTHCHECK = "DS-0026"  # LOW, no StartLine
_PLANT_PRIVILEGED = "KSV-0017"  # HIGH, on the privileged Pod


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


def _enqueue_trivy_scan(client: httpx.Client) -> str:
    target = _post_repo_target(client)
    response = client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "trivy"},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def test_trivy_scan_finds_iac_misconfigurations(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """End-to-end: clone, trivy fs --scanners misconfig, persist, surface.

    Floor assertion (``in {row.rule_id for row in rows}`` for the
    planted IDs) rather than equality — Trivy's bundled ruleset
    grows across versions and additional rules may fire on the
    same plants.  The contract is "the planted high-severity
    rules are detected"; surfacing more is operationally fine.
    """
    scan_id = _enqueue_trivy_scan(api_client)
    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body
    # API surfaces the resolved scanner name on the response.
    assert body["scanner"] == "trivy", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    assert rows, "Trivy scan against IaC plants produced zero CodeFinding rows"

    # Trivy IaC findings have NULL secret_kind / secret_hash /
    # column_number / commit_sha (per the plugin contract).
    for r in rows:
        assert r.secret_kind is None, r
        assert r.secret_hash is None, r
        assert r.column_number is None, r
        assert r.commit_sha is None, r

    rule_ids = {r.rule_id for r in rows}
    files = {r.file_path for r in rows}

    # Each planted rule must surface at least once.
    for rule_id in (
        _PLANT_LATEST_TAG,
        _PLANT_ROOT_USER,
        _PLANT_NO_HEALTHCHECK,
        _PLANT_PRIVILEGED,
    ):
        assert rule_id in rule_ids, f"missing planted rule {rule_id!r}; got {sorted(rule_ids)}"

    # Both planted files surface in some row's file_path.
    assert _PLANTED_DOCKERFILE in files, files
    assert _PLANTED_POD in files, files

    # Surface on the API too — code_findings populated, findings empty.
    assert len(body["code_findings"]) >= 4, body["code_findings"]
    assert body["findings"] == [], body["findings"]


def test_trivy_scan_severity_mapping(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Persisted severity values are zynksec enum (low/medium/high/critical),
    not raw Trivy values (LOW/MEDIUM/HIGH/CRITICAL).

    Trivy's mapping is a direct lowercase — no boundary logic
    like OSV's CVSS bucketing — but a regression that dropped
    the lower-casing would surface here as ``"HIGH" != "high"``.
    """
    scan_id = _enqueue_trivy_scan(api_client)
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
    raw_trivy_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    for r in rows:
        assert r.severity in valid_severities, f"row severity {r.severity!r} not in zynksec enum"
        assert (
            r.severity not in raw_trivy_severities
        ), f"row severity {r.severity!r} is a raw Trivy value — the classifier didn't map it"

    # Pin the planted high-severity rule (USER root → DS-0002 → HIGH).
    user_root = [r for r in rows if r.rule_id == _PLANT_ROOT_USER]
    assert user_root, "DS-0002 plant didn't surface a finding"
    assert user_root[0].severity == "high", user_root[0]


def test_trivy_scan_persists_null_line_for_no_healthcheck(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """DS-0026 ("No HEALTHCHECK defined") fires on the *absence* of a
    directive, so Trivy has no StartLine to point at.  Assert the
    persisted CodeFinding row's ``line_number`` is NULL — exercising
    migration 0009 end-to-end through the Trivy path.

    This is the IaC analogue of OSV-Scanner's "package-shaped, not
    line-shaped" property: not every finding has a line context,
    and the schema has to accommodate that.
    """
    scan_id = _enqueue_trivy_scan(api_client)
    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body

    no_healthcheck = (
        db_session.execute(
            select(CodeFinding)
            .where(CodeFinding.scan_id == uuid.UUID(scan_id))
            .where(CodeFinding.rule_id == _PLANT_NO_HEALTHCHECK),
        )
        .scalars()
        .all()
    )
    assert no_healthcheck, f"{_PLANT_NO_HEALTHCHECK} plant didn't surface a finding"
    for r in no_healthcheck:
        assert (
            r.line_number is None
        ), f"{_PLANT_NO_HEALTHCHECK} should persist line_number=None; got {r.line_number!r}"
        assert r.file_path == _PLANTED_DOCKERFILE, r


def test_unknown_scanner_lists_all_four(api_client: httpx.Client) -> None:
    """POST /scans with ``scanner="bogus"`` → canonical 422
    ``unknown_scanner`` with ``details.available`` listing all
    four kind=repo scanner names post-Sprint-4.

    Subset assertion (``issubset`` not equality) future-proofs
    against later additions while still catching a regression
    that drops one of the existing four.
    """
    target = _post_repo_target(api_client)
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "bogus"},
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "unknown_scanner", body
    assert body["request_id"], body
    details = body.get("details") or {}
    assert details.get("requested") == "bogus", details
    assert details.get("kind") == "repo", details
    available = set(details.get("available") or [])
    assert {"gitleaks", "semgrep", "osv-scanner", "trivy"}.issubset(available), available
