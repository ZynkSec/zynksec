"""Phase 3 Sprint 1 — Gitleaks end-to-end against the served fixture repo.

CLAUDE.md §7 — real Postgres, real Redis, real Celery, real
gitleaks binary inside the code-worker, real bare git repo served
over HTTP by the ``gitfixture`` service.  No mocks.

Five tests, one assertion theme each:

1. The gitleaks scan finds **exactly the three planted secrets** at
   the right files + line numbers + severity (the contract the
   plugin's rule-id classifier promises).

2. The persisted ``CodeFinding`` rows carry ``redacted_preview``
   that does NOT contain the plaintext secret value (CLAUDE.md §6
   security regression guard — separate test, separate signal).

3. ``POST /api/v1/targets`` with ``kind=repo`` and an ``ssh://`` /
   ``file://`` URL returns 422 with the canonical envelope.

4. A scan against a ``kind=repo`` Target persists
   ``Scan.assigned_queue == "code_q"`` (NOT a ZAP queue), proving
   the dispatcher routes correctly.

5. The pre-existing ZAP scans (juice-shop PASSIVE, ScanGroup
   round-robin) still pass — handled implicitly by running the
   whole integration suite, but documented here as a constraint
   the new sprint must not regress.
"""

from __future__ import annotations

import subprocess  # noqa: S404 — list-form docker exec probes, no shell
import time
import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import CodeFinding, Scan

# ----------------------------------------------------------------------
# Sprint-tuning knobs.  Phase 3 Sprint 1 gitleaks scans are seconds,
# not minutes — the per-test timeout exists for diagnostics, not for
# legitimately-long runs.  CI on a noisy runner sometimes spikes the
# clone step into the 30-second range; the 180 s budget below leaves
# room without hiding a regression that doubled the scan duration.
# ----------------------------------------------------------------------
_TERMINAL_POLL_INTERVAL_S = 1.0
_TERMINAL_BUDGET_S = 180.0


_FIXTURE_REPO_URL = "http://gitfixture/vulnerable-repo.git"

# Plant catalogue — must match ``tests/fixtures/vulnerable-repo-src/``.
# File paths are relative to the repo root (which is what gitleaks
# emits and what ``CodeFinding.file_path`` stores).  Line numbers are
# 1-indexed and account for the leading comment lines in each plant
# file — adjust here if the fixture files change.
_EXPECTED_PLANTS: list[dict[str, object]] = [
    {
        "file_path": "config/aws_credentials.txt",
        "line_number": 5,
        "secret_kind_substring": "AWS",
        "severity": "critical",
        # Substring of the literal plant value; this test asserts the
        # redacted_preview does NOT contain it (security guard #2).
        "plaintext_substring": "IOSFODNN7TESTKEY",
    },
    {
        "file_path": "secrets/github_token.txt",
        "line_number": 5,
        "secret_kind_substring": "Source-host",
        "severity": "high",
        "plaintext_substring": "TESTONLYNOTREAL",
    },
    {
        "file_path": "webhooks/slack.yaml",
        "line_number": 5,
        "secret_kind_substring": "Third-party",
        "severity": "high",
        "plaintext_substring": "TTESTONLY00000000",
    },
]


def _create_repo_target(client: httpx.Client, *, name: str | None = None) -> dict:
    """POST /api/v1/targets with kind=repo + the served fixture URL.

    Test-mode env vars on the API container relax the cloner's
    allow-list to admit ``http://gitfixture`` — production
    deployments don't carry those vars and would 422 here.
    """
    body = {
        "name": name or f"vuln-repo-{uuid.uuid4().hex[:8]}",
        "url": _FIXTURE_REPO_URL,
        "kind": "repo",
    }
    response = client.post("/api/v1/targets", json=body)
    assert response.status_code == 201, response.text
    return response.json()


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


def test_gitleaks_scan_finds_planted_secrets(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """End-to-end: clone, scan, persist, surface — three plants found.

    The strict assertion (``count == 3``) is the contract this sprint
    promises.  Anything other than three implies either gitleaks
    rule-set drift (their default rules dropped one of the AWS /
    GitHub / Slack matchers) or a regression in the cloner /
    dispatcher / plugin path — all of which the operator wants
    surfaced loudly, not absorbed into a "more is fine" ``>= 3``.
    """
    target = _create_repo_target(api_client)

    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    assert len(rows) == 3, (
        f"expected exactly 3 plants; got {len(rows)}: "
        f"{[(r.file_path, r.rule_id, r.severity) for r in rows]}"
    )

    by_file = {r.file_path: r for r in rows}
    for plant in _EXPECTED_PLANTS:
        assert plant["file_path"] in by_file, (
            f"missing plant for {plant['file_path']!r}; " f"got files {sorted(by_file)}"
        )
        row = by_file[plant["file_path"]]  # type: ignore[index]
        assert row.line_number == plant["line_number"], (
            f"{plant['file_path']}: expected line {plant['line_number']!r}, "
            f"got {row.line_number}"
        )
        assert row.severity == plant["severity"], (
            f"{plant['file_path']}: expected severity {plant['severity']!r}, "
            f"got {row.severity!r}"
        )
        assert plant["secret_kind_substring"] in row.secret_kind, (  # type: ignore[operator]
            f"{plant['file_path']}: secret_kind {row.secret_kind!r} "
            f"does not contain {plant['secret_kind_substring']!r}"
        )

    # Surface on the API too — the GET handler must populate
    # ``code_findings`` (not the HTTP-shaped ``findings``).
    assert len(body["code_findings"]) == 3, body["code_findings"]
    assert body["findings"] == [], body["findings"]


def test_gitleaks_scan_redacts_secrets(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Security regression guard — DB rows must NEVER carry plaintext.

    Separate test (one assertion theme) so a regression that lets the
    raw secret slip into ``redacted_preview`` is impossible to miss
    in CI output.  Asserts both columns the API surfaces
    (``redacted_preview``) AND the column it doesn't (``secret_hash``,
    which is the SHA-256 hex digest — verified via length + charset
    rather than equality, since computing the digest in the test
    would just duplicate the production code).
    """
    target = _create_repo_target(api_client)
    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202
    scan_id = response.json()["id"]

    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    assert rows, "no CodeFinding rows persisted; cannot assert redaction"

    plaintext_substrings = {p["plaintext_substring"] for p in _EXPECTED_PLANTS}

    for row in rows:
        # Redacted preview must not contain ANY of the plaintext
        # substrings (we don't know which plant matched which row
        # without re-deriving the mapping; asserting against the
        # whole set is strictly tighter than a per-row check).
        for needle in plaintext_substrings:
            assert needle not in row.redacted_preview, (
                f"plaintext substring {needle!r} leaked into "
                f"redacted_preview for {row.file_path}: "
                f"{row.redacted_preview!r}"
            )
        # SHA-256 hex digest = 64 lowercase hex chars.  This verifies
        # we hashed the secret (one-way) rather than stored it.
        assert len(row.secret_hash) == 64
        assert all(c in "0123456789abcdef" for c in row.secret_hash)


@pytest.mark.parametrize(
    "bad_url",
    [
        "ssh://git@github.com/owner/repo.git",
        "file:///etc/passwd",
        "git://github.com/owner/repo.git",
    ],
)
def test_repo_target_creation_rejects_ssh_and_file_urls(
    api_client: httpx.Client,
    bad_url: str,
) -> None:
    """The cloner's allow-list is enforced at write-time too.

    POSTing ``kind=repo`` with a forbidden scheme must surface as a
    canonical-envelope 422 — not a 500, not a Pydantic-default
    ``{"detail": [...]}`` shape.  The exact code is
    ``request_validation_error`` because Pydantic's ``HttpUrl``
    rejects non-http(s) schemes before our ``model_validator``
    runs; the canonical-envelope handler in
    :mod:`zynksec_api.main` flattens that into our shape.
    """
    response = api_client.post(
        "/api/v1/targets",
        json={
            "name": f"bad-{uuid.uuid4().hex[:8]}",
            "url": bad_url,
            "kind": "repo",
        },
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "request_validation_error", body
    assert body["request_id"], body
    # ``details.errors`` carries the per-field Pydantic errors;
    # don't assert exact wording (Pydantic minor versions tweak
    # messages) — assert the URL field was flagged.
    errors = body["details"]["errors"]
    assert any("url" in str(err.get("loc", ())) for err in errors), body


def test_scan_repo_target_routes_to_code_queue(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Dispatch contract: ``kind=repo`` -> ``Scan.assigned_queue == 'code_q'``.

    Doesn't wait for the scan to terminate — the assertion is on
    the queue name persisted at enqueue time, which is committed
    inside the same transaction as the Scan row (router enforces
    "no enqueue without record, no record without enqueue").  Tests
    the routing layer in isolation from the gitleaks plugin's
    end-to-end behaviour (covered by
    ``test_gitleaks_scan_finds_planted_secrets``).
    """
    target = _create_repo_target(api_client)
    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    row = db_session.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id)),
    ).scalar_one()
    assert (
        row.assigned_queue == "code_q"
    ), f"repo Target dispatched to {row.assigned_queue!r}, expected 'code_q'"
    # Sanity: ZAP queues should not have been picked.  Loose check
    # that the value isn't ``zap_q_*`` — protects against a future
    # registry edit that returns a non-empty but ZAP-shaped queue.
    assert not (row.assigned_queue or "").startswith("zap_q_"), row.assigned_queue


def test_gitleaks_scan_cleans_up_all_disk_residue(
    api_client: httpx.Client,
) -> None:
    """Pre-merge security-review BLOCKER #1 regression guard.

    The plugin writes gitleaks' JSON report (containing plaintext
    ``Match`` / ``Secret`` fields) to ``<scan_id>/gitleaks.json``,
    sibling of the cloned repo.  Pre-fix, the cloner's teardown
    only ``rmtree``'d the ``<scan_id>/repo/`` subdirectory — so
    every scan accumulated a permanent on-disk credential dump
    under ``/tmp/zynksec-scans/<scan_id>/gitleaks.json``.

    Post-fix, teardown nukes the whole ``<scan_id>/`` root, which
    is the single source of truth for "this scan is done, drop
    everything."  This test asserts that invariant by listing
    ``/tmp/zynksec-scans/`` from inside the code-worker
    container after a scan completes — the scan's directory must
    not exist.

    Runs the assertion on BOTH the success path (a successful
    scan against the gitfixture) AND the failure path (a clone
    that gets rejected by the validator before any disk work
    happens — the scan_id directory should still not be present
    after the failed scan).  Both signals matter: a regression
    that only cleaned up on success would leave plaintext residue
    behind every clone that timed out, hit a network blip, or
    otherwise tripped the ``CalledProcessError`` path.
    """

    def _scan_dir_exists_in_worker(scan_id: str) -> bool:
        """Probe the code-worker container for a leftover scan root.

        The path under test is the runtime tempdir layout the cloner
        creates inside the container — same convention as
        ``packages/scanners/.../repo/cloner.py:_scan_root``.  The
        S108 "/tmp insecure" lint exception applies because we're
        asserting on a path the SUT writes; we're not creating
        anything here.
        """
        scan_path = f"/tmp/zynksec-scans/{scan_id}"  # noqa: S108 — SUT-owned path
        # ``docker`` is on PATH inside the integration test runner;
        # using a partial executable path is intentional for
        # portability across CI runners (S607 noqa).
        cmd = ["docker", "exec", "zynksec-code-worker", "test", "-e", scan_path]  # noqa: S607
        result = subprocess.run(  # noqa: S603 — list-form, fixed args
            cmd,
            check=False,
            capture_output=True,
        )
        # ``test -e`` exits 0 if the path exists, 1 if not.
        return result.returncode == 0

    # ---------- Success path ----------
    target = _create_repo_target(api_client)
    response = api_client.post("/api/v1/scans", json={"target_id": target["id"]})
    assert response.status_code == 202
    success_scan_id = response.json()["id"]
    body = _wait_for_terminal(api_client, success_scan_id)
    assert body["status"] == "completed", body

    # rmtree races on debian's tmpfs sometimes lag a moment after
    # the worker logs its terminal status; give the kernel a tick
    # before asserting the path is gone.
    deadline = time.monotonic() + 10.0
    while _scan_dir_exists_in_worker(success_scan_id) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not _scan_dir_exists_in_worker(success_scan_id), (
        f"after a successful scan, /tmp/zynksec-scans/{success_scan_id}/ still "
        "exists in the code-worker container — gitleaks.json (plaintext "
        "secrets!) is leaking past teardown"
    )

    # ---------- Failure path ----------
    # Hit a URL the cloner accepts (host on the test allow-list)
    # but for which ``git clone`` fails — a non-existent repo on
    # the gitfixture server returns 404 from git-http-backend,
    # which surfaces as ``CalledProcessError`` inside the cloner.
    # That code path also rmtree's ``root`` (line 236-ish in
    # cloner.py); the assertion verifies the failure path matches
    # the success path.
    fail_target_response = api_client.post(
        "/api/v1/targets",
        json={
            "name": f"nonexistent-{uuid.uuid4().hex[:8]}",
            "url": "http://gitfixture/does-not-exist.git",
            "kind": "repo",
        },
    )
    assert fail_target_response.status_code == 201, fail_target_response.text
    fail_target = fail_target_response.json()
    fail_response = api_client.post(
        "/api/v1/scans",
        json={"target_id": fail_target["id"]},
    )
    assert fail_response.status_code == 202
    fail_scan_id = fail_response.json()["id"]
    fail_body = _wait_for_terminal(api_client, fail_scan_id)
    assert fail_body["status"] == "failed", fail_body

    deadline = time.monotonic() + 10.0
    while _scan_dir_exists_in_worker(fail_scan_id) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not _scan_dir_exists_in_worker(fail_scan_id), (
        f"after a failed scan, /tmp/zynksec-scans/{fail_scan_id}/ still "
        "exists in the code-worker container — even the error path must "
        "wipe the per-scan tempdir"
    )
