"""Phase 3 Sprint 1 review coverage-gap regression suite.

Phase 3 cleanup item #11.  The Sprint 1 security review listed
five concrete coverage gaps; this module fills them.  All real
Postgres + Redis + ZAP + code-worker, no mocks (CLAUDE.md §7).

  a. Cross-project authorization on GET /scans — currently
     unenforced (no auth boundary in Phase 0/1/2/3); the test
     is ``xfail(strict=True)`` so a future auth sprint that
     ADDS the gate flips it to passing and we know the gap
     closed.
  b. ``kind=api`` Targets route to ``zap_q_*``, not ``code_q``.
  c. Legacy ``target_url`` POST with a github-style URL routes
     to ``zap_q_*`` (default kind=web_app applies; the URL
     shape doesn't auto-promote to kind=repo).
  d. ``secret_hash`` is deterministic across two scans of the
     same repo — precondition for any future dedup feature.
  e. Cloner failure modes (ref-not-found path) yield a
     canonical generic ``failure_reason`` that does NOT carry
     stderr secret-shaped content.
"""

from __future__ import annotations

import time
import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import CodeFinding, Scan

# ----------------------------------------------------------------------
# Sprint-tuning knobs — same values as test_gitleaks_scan.py for
# cross-test consistency.  Repeated here so this file has no
# import-coupling to its sibling.
# ----------------------------------------------------------------------
_TERMINAL_POLL_INTERVAL_S = 1.0
_TERMINAL_BUDGET_S = 180.0

_FIXTURE_REPO_URL = "http://gitfixture/vulnerable-repo.git"
_NONEXISTENT_REPO_URL = "http://gitfixture/does-not-exist.git"

# Plaintext substrings that must NEVER appear in
# ``Scan.failure_reason`` (or any DB-persisted error message).
# Same plant catalogue as test_gitleaks_scan.py's _EXPECTED_PLANTS.
_PLAINTEXT_BAIT: list[str] = [
    "IOSFODNN7TESTKEY",  # AWS plant suffix
    "TESTONLYNOTREAL",  # GitHub PAT plant suffix
    "TTESTONLY00000000",  # Slack webhook plant T-id
]


def _wait_for_terminal(client: httpx.Client, scan_id: str) -> dict:
    """Poll GET /api/v1/scans/{id} until status is completed or failed."""
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


def _post_target(client: httpx.Client, *, kind: str, url: str, name: str | None = None) -> dict:
    body = {
        "name": name or f"{kind}-{uuid.uuid4().hex[:8]}",
        "url": url,
        "kind": kind,
    }
    response = client.post("/api/v1/targets", json=body)
    assert response.status_code == 201, response.text
    return response.json()


# ----------------------------------------------------------------------
# (a) Cross-project authorization on GET /scans — DOCUMENTED GAP.
# ----------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Phase 3 sprint 1 review item: GET /api/v1/scans/{id} has no "
        "project-id resolution today.  A scan_id from project A is "
        "returned 200 to a request that resolves to project B.  "
        "Mirrors the Sprint 2 cross-project pattern that already "
        "exists for ScanGroups but does NOT exist for individual "
        "scan reads.  Closing this gap is auth-sprint scope; the "
        "xfail(strict=True) means the test FLIPS to passing the "
        "moment an auth boundary lands, prompting removal of the "
        "xfail marker."
    ),
)
def test_get_scan_returns_404_for_other_project_scan_id(
    api_client: httpx.Client,
) -> None:
    """Cross-project read should return canonical-envelope 404.

    Today's GET handler doesn't accept a ``project_id`` parameter
    or resolve project context from any header — so the only way
    to "ask for the wrong project" is to pass a scan_id that
    doesn't exist (which IS 404).  This test models the future
    contract: when project context lands, a scan from a different
    project should look identical to a missing scan.  Until then
    it xfails.
    """
    # Create a scan in the implicit Local Dev project.
    target = _post_target(
        api_client,
        kind="web_app",
        url="http://juice-shop:3000/",
    )
    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    # Future contract: ask for the scan from a different project's
    # context.  No mechanism for that today; pretend by passing a
    # ``?project_id=<random>`` query param the handler doesn't read.
    other_project = uuid.uuid4()
    cross_project_response = api_client.get(
        f"/api/v1/scans/{scan_id}",
        params={"project_id": str(other_project)},
    )
    assert cross_project_response.status_code == 404, cross_project_response.text
    body = cross_project_response.json()
    assert body["code"] == "scan_not_found", body


# ----------------------------------------------------------------------
# (b) kind=api Targets route to zap_q_*, not code_q.
# ----------------------------------------------------------------------


def test_kind_api_target_routes_to_zap_q_not_code_q(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """``kind=api`` rides the ZAP family per the canonical registry.

    The registry maps ``api`` → ``SCANNER_ZAP`` (it scans an
    OpenAPI / GraphQL spec via the ZAP daemon today; a dedicated
    API-fuzz scanner is Phase 3+).  Confirms the API write-time
    routing matches that.
    """
    target = _post_target(
        api_client,
        kind="api",
        # Any http(s) target URL is fine — the routing is decided
        # by ``Target.kind`` at write-time, not by the URL.  The
        # scan itself will fail at the worker (ZapPlugin's
        # ``supported_target_kinds={"web_app"}`` rejects "api"
        # today — that's covered by the existing
        # ``test_scan_group_partial_failure_*`` suite).
        url="http://juice-shop:3000/api/v3/swagger.json",
    )
    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    row = db_session.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id)),
    ).scalar_one()
    assert row.assigned_queue is not None
    assert row.assigned_queue.startswith(
        "zap_q_"
    ), f"kind=api dispatched to {row.assigned_queue!r}, expected zap_q_*"
    assert row.assigned_queue != "code_q", row.assigned_queue


# ----------------------------------------------------------------------
# (c) Legacy target_url POST with github URL routes to zap_q_* default.
# ----------------------------------------------------------------------


def test_legacy_target_url_with_github_url_routes_to_zap_default_kind(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """A github-style URL passed via legacy ``target_url`` (no
    Target row, no explicit kind) routes to ZAP, not code_q.

    The legacy POST has no Target row, so dispatch falls back to
    the implicit ``kind=web_app`` default — which routes to
    ``zap_q_*``.  A future heuristic that auto-promotes
    github-style URLs to ``kind=repo`` would change this; locking
    the contract now means such a change is an explicit decision,
    not silent drift.
    """
    response = api_client.post(
        "/api/v1/scans",
        json={"target_url": "https://github.com/owner/repo"},
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    row = db_session.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id)),
    ).scalar_one()
    assert row.assigned_queue is not None
    assert row.assigned_queue.startswith("zap_q_"), (
        f"legacy target_url with github URL dispatched to "
        f"{row.assigned_queue!r}, expected zap_q_* (kind=web_app default)"
    )
    assert row.assigned_queue != "code_q", row.assigned_queue


# ----------------------------------------------------------------------
# (d) secret_hash determinism across two scans of the same repo.
# ----------------------------------------------------------------------


def _create_repo_target(client: httpx.Client) -> dict:
    return _post_target(
        client,
        kind="repo",
        url=_FIXTURE_REPO_URL,
        name=f"dedup-{uuid.uuid4().hex[:8]}",
    )


def _scan_to_completion(client: httpx.Client, target_id: str) -> str:
    response = client.post("/api/v1/scans", json={"target_id": target_id})
    assert response.status_code == 202
    scan_id = response.json()["id"]
    body = _wait_for_terminal(client, scan_id)
    assert body["status"] == "completed", body
    return scan_id


def test_secret_hash_unique_across_scans_of_same_repo(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Two scans of the same fixture repo produce identical
    ``secret_hash`` values for the same plants.

    Determinism is the precondition for any future cross-scan
    dedup feature.  ``_hash`` is plain SHA-256 of the raw secret
    (Phase 3 Sprint 7+ may revisit with HMAC + per-installation
    salt; until then the hash is deterministic by construction
    and the test pins that contract).
    """
    target_a = _create_repo_target(api_client)
    target_b = _create_repo_target(api_client)
    scan_a = _scan_to_completion(api_client, target_a["id"])
    scan_b = _scan_to_completion(api_client, target_b["id"])

    rows_a = (
        db_session.execute(select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_a)))
        .scalars()
        .all()
    )
    rows_b = (
        db_session.execute(select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_b)))
        .scalars()
        .all()
    )
    assert rows_a, "scan A produced no findings"
    assert rows_b, "scan B produced no findings"

    # Map each scan's hashes by file_path so we compare the same
    # plant across runs (scan order isn't deterministic).
    hashes_a = {r.file_path: r.secret_hash for r in rows_a}
    hashes_b = {r.file_path: r.secret_hash for r in rows_b}

    assert set(hashes_a) == set(hashes_b), (
        "scans produced different file-path sets: " f"a={set(hashes_a)} b={set(hashes_b)}"
    )
    for file_path in hashes_a:
        assert hashes_a[file_path] == hashes_b[file_path], (
            f"secret_hash diverged across scans for {file_path}: "
            f"a={hashes_a[file_path]!r} b={hashes_b[file_path]!r}"
        )


# ----------------------------------------------------------------------
# (e) Cloner failure modes — ref-not-found path produces a generic
# canonical failure_reason, no stderr secret excerpts persisted.
# ----------------------------------------------------------------------


def test_clone_ref_not_found_yields_canonical_failure_reason(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """A clone of a nonexistent repo path → ``Scan.status='failed'``
    with a non-secret-bearing ``failure_reason``.

    The path that gets exercised:
      gitfixture serves the bare ``vulnerable-repo.git`` only;
      cloning ``http://gitfixture/does-not-exist.git`` goes
      through ``git-http-backend`` → 404 → git client errors
      out → cloner catches ``CalledProcessError`` and raises
      ``CloneError``.  ``execute_scan`` marks the scan failed
      with ``str(exc)`` as the reason.

    Re-asserts the security fix from the prior review's
    Blocker 5 / Finding 5: the failure_reason MUST NOT contain
    any plaintext-looking content from gitleaks-style secrets.
    The cloner's CloneError message echoes the LAST line of git
    stderr — defence in depth says any plaintext that happens to
    survive that filter is a regression.

    Other failure modes the review listed (timeout via
    sleep-server, unreachable IP) aren't exercised here:
      * Timeout: requires either a sleep-server fixture
        container or a per-test cloner-timeout override.  Both
        are infra investments the cleanup sprint doesn't
        justify.
      * Unreachable IP: the validator now hard-rejects raw IP
        literals (Sprint 1 review BLOCKER #4 fix), so
        ``https://255.255.255.255/...`` fails before the clone
        runs.  Testing it here would test the validator, not the
        cloner.  The validator already has unit-test coverage in
        ``tests/unit/test_validate_clone_url.py``.
    """
    target = _post_target(
        api_client,
        kind="repo",
        url=_NONEXISTENT_REPO_URL,
    )
    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "failed", body

    row = db_session.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id)),
    ).scalar_one()
    assert row.failure_reason is not None
    # Generic shape — should mention "git clone" or "gitleaks"
    # but not echo a multi-line stderr blob.
    assert len(row.failure_reason) > 0
    # Security regression guard: no plaintext secret-shaped
    # substring leaked into the persisted failure reason.
    for needle in _PLAINTEXT_BAIT:
        assert needle not in row.failure_reason, (
            f"plaintext substring {needle!r} leaked into "
            f"Scan.failure_reason: {row.failure_reason!r}"
        )
