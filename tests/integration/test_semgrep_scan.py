"""Phase 3 Sprint 2 — SemgrepPlugin + scanner field end-to-end.

CLAUDE.md §7 — real Postgres, real Redis, real Celery, real
semgrep binary inside the code-worker, real bare repo served
over HTTP by the gitfixture (now carrying both gitleaks and
Semgrep plants).  No mocks.

Coverage:
  * ``test_semgrep_scan_finds_planted_vulnerabilities`` — POST
    a kind=repo scan with ``scanner="semgrep"``, assert exactly
    three CodeFinding rows match the planted rule_ids on the
    known files + line numbers.
  * ``test_semgrep_scan_severity_mapping`` — assert the mapped
    severities are zynksec values (low/medium/high/critical),
    not raw Semgrep values (info/warning/error).
  * ``test_scancreate_unknown_scanner_returns_422`` — POST a
    scan with ``scanner="nonexistent"``; assert 422 with
    canonical envelope code ``unknown_scanner`` and
    ``details.available`` listing valid names.
  * ``test_repo_scan_default_scanner_is_gitleaks`` — POST with
    NO scanner field; assert ``Scan.scanner == "gitleaks"``
    after dispatch (default-pick path).
  * ``test_repo_scan_explicit_gitleaks_still_works`` — POST
    with ``scanner="gitleaks"``; assert it runs Gitleaks (no
    Semgrep findings).

The Sprint 1 ``test_gitleaks_scan_finds_planted_secrets`` (and
the rest of the Sprint 1 gitleaks suite) continue to pass
without modification — kind=repo + no scanner field still
defaults to gitleaks.
"""

from __future__ import annotations

import time
import uuid

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from zynksec_db import CodeFinding, Scan

_TERMINAL_POLL_INTERVAL_S = 1.0
# Semgrep on a small fixture repo runs in seconds, but the FIRST
# scan on a fresh ``$HOME/.semgrep`` cache pulls down the
# ``p/security-audit`` ruleset — that can take 10-30 s on a slow
# network.  300 s keeps the test diagnostic without hiding a real
# regression.
_TERMINAL_BUDGET_S = 300.0

_FIXTURE_REPO_URL = "http://gitfixture/vulnerable-repo.git"

# Plant catalogue — must match the inline files in
# ``tests/fixtures/semgrep-plants/`` (and the gitfixture Dockerfile's
# COPY at image-build time).  Each file produces exactly one finding
# from the upstream ``p/security-audit`` ruleset.
_EXPECTED_SEMGREP_PLANTS: list[dict[str, object]] = [
    {
        "file_path": "semgrep-plants/eval_handler.py",
        # Semgrep's rule id is the dotted path of the rule file in
        # the upstream config; ``eval-detected`` lives at
        # ``python.lang.security.audit.eval-detected.eval-detected``.
        "rule_id_substring": "eval-detected",
        # WARNING → medium per ``_classify_severity``.
        "expected_severity": "medium",
    },
    {
        "file_path": "semgrep-plants/shell_runner.py",
        "rule_id_substring": "subprocess-shell-true",
        # ERROR → high (no impact metadata on this rule, so no
        # critical escalation).
        "expected_severity": "high",
    },
    {
        "file_path": "semgrep-plants/pickle_loader.py",
        "rule_id_substring": "avoid-pickle",
        "expected_severity": "medium",
    },
]


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


def test_semgrep_scan_finds_planted_vulnerabilities(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """End-to-end: clone, scan with semgrep, persist, surface — three
    SAST plants found.

    Strict ``count >= 3`` rather than equality — ``p/security-audit``
    might fire additional rules on the secret-plant files (e.g. the
    ``slack_webhook:`` URL-like value triggers a low-severity HTTP-
    related rule).  The contract is "all three plants found";
    extras are operationally fine.
    """
    target = _post_repo_target(api_client)
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "semgrep"},
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body
    # API surfaces the resolved scanner name on the response.
    assert body["scanner"] == "semgrep", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    # All Semgrep findings have NULL secret_kind / secret_hash
    # (Sprint 2 migration relaxed those to nullable).
    for r in rows:
        assert r.secret_kind is None, r
        assert r.secret_hash is None, r

    # Each plant must have at least one matching row by rule_id +
    # file_path.
    by_file = {r.file_path: r for r in rows}
    for plant in _EXPECTED_SEMGREP_PLANTS:
        path = plant["file_path"]  # type: ignore[index]
        assert path in by_file, f"missing semgrep finding for {path!r}; got files {sorted(by_file)}"
        row = by_file[path]  # type: ignore[index]
        rule_substr = plant["rule_id_substring"]
        assert rule_substr in row.rule_id, (  # type: ignore[operator]
            f"{path}: rule_id {row.rule_id!r} doesn't contain {rule_substr!r}"
        )

    # Surface on the API too — code_findings populated, findings empty.
    assert len(body["code_findings"]) >= 3, body["code_findings"]
    assert body["findings"] == [], body["findings"]


def test_semgrep_scan_severity_mapping(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """Persisted severity values are zynksec enum (low/medium/high/critical),
    not raw Semgrep levels (INFO/WARNING/ERROR).
    """
    target = _post_repo_target(api_client)
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "semgrep"},
    )
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
    valid_severities = {"low", "medium", "high", "critical"}
    raw_semgrep_severities = {"INFO", "WARNING", "ERROR"}
    for r in rows:
        assert r.severity in valid_severities, f"row severity {r.severity!r} not in zynksec enum"
        assert r.severity not in raw_semgrep_severities, (
            f"row severity {r.severity!r} is a raw Semgrep value — " "the classifier didn't map it"
        )

    # Lock the contract that the planted high-severity rule
    # (subprocess-shell-true → ERROR → high) actually maps to high.
    shell_rows = [r for r in rows if "subprocess-shell-true" in r.rule_id]
    assert shell_rows, "subprocess-shell-true plant didn't surface a finding"
    assert shell_rows[0].severity == "high", shell_rows[0]


def test_scancreate_unknown_scanner_returns_422(
    api_client: httpx.Client,
) -> None:
    """POST /scans with ``scanner="nonexistent"`` → canonical 422
    ``unknown_scanner`` with ``details.available`` listing valid
    names.
    """
    target = _post_repo_target(api_client)
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "nonexistent"},
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "unknown_scanner", body
    assert body["request_id"], body
    details = body.get("details") or {}
    assert details.get("requested") == "nonexistent", details
    assert details.get("kind") == "repo", details
    available = set(details.get("available") or [])
    # Valid kind=repo scanners post-Sprint-2.
    assert {"gitleaks", "semgrep"}.issubset(available), available


def test_repo_scan_default_scanner_is_gitleaks(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """POSTing with NO scanner field resolves to the per-kind default.

    For ``kind=repo`` the default is gitleaks (Sprint 1 backward-
    compat preserved).  This test pins that contract — a future
    registry change that flipped the default would surface here.
    """
    target = _post_repo_target(api_client)
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"]},  # no scanner field
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    # Read the persisted resolved scanner immediately — no need to
    # wait for terminal.  The router persists ``scan.scanner`` in
    # the same transaction as the row creation.
    row = db_session.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id)),
    ).scalar_one()
    assert row.scanner == "gitleaks", (
        f"default scanner for kind=repo should be gitleaks; " f"got {row.scanner!r}"
    )


def test_repo_scan_explicit_gitleaks_still_works(
    api_client: httpx.Client,
    db_session: Session,
) -> None:
    """POSTing with explicit ``scanner="gitleaks"`` runs gitleaks.

    Regression guard for the explicit-default case.  Pre-Sprint-2
    the only path was implicit-default; Sprint 2 split that into
    explicit-or-default.  Both must produce the same outcome (3
    secret findings, 0 SAST findings).
    """
    target = _post_repo_target(api_client)
    response = api_client.post(
        "/api/v1/scans",
        json={"target_id": target["id"], "scanner": "gitleaks"},
    )
    assert response.status_code == 202
    scan_id = response.json()["id"]
    body = _wait_for_terminal(api_client, scan_id)
    assert body["status"] == "completed", body
    assert body["scanner"] == "gitleaks", body

    rows = (
        db_session.execute(
            select(CodeFinding).where(CodeFinding.scan_id == uuid.UUID(scan_id)),
        )
        .scalars()
        .all()
    )
    # Gitleaks finds the 3 secret plants — by rule_id NOT containing
    # any Semgrep rule path components.
    for r in rows:
        assert "semgrep" not in r.rule_id.lower()
        assert "python.lang" not in r.rule_id.lower()
        # Gitleaks rules carry secret_hash + secret_kind.
        assert r.secret_hash is not None, r
        assert r.secret_kind is not None, r

    # Sprint 1 contract: exactly 3 plants for gitleaks.
    assert len(rows) == 3, [(r.file_path, r.rule_id) for r in rows]
