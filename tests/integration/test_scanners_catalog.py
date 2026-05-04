"""GET /api/v1/scanners catalogue endpoint — Phase 4 Sprint 2.

Real Postgres + Redis (CLAUDE.md §7).  No mocks.  The endpoint
sources its response from the plugin registry; this test pins the
contract that:

  * Every kind the platform supports (web_app / api / repo) appears
    as a key.
  * The scanner list per kind matches ``scanners_for_kind(kind)``
    exactly — a future plugin addition that lands in the registry
    must surface here without a router edit.
  * The default flag is set on exactly one scanner per kind (the
    one ``default_scanner_for(kind)`` returns).
  * ``scan_profiles`` carries the three ZAP intensities for
    web_app / api and is empty for repo (matches every code
    scanner's ``supported_intensities = {PASSIVE}``).

The endpoint is metadata — no auth, no project scoping — so the
test calls it directly with no setup beyond the API being up.
"""

from __future__ import annotations

import httpx


def test_scanners_catalog_lists_every_kind(api_client: httpx.Client) -> None:
    response = api_client.get("/api/v1/scanners")
    assert response.status_code == 200, response.text
    body = response.json()

    # Top-level shape: a single ``kinds`` mapping keyed on the
    # three known TargetKind values.  Pinning the key set
    # future-proofs against a typo in a future plugin landing.
    assert "kinds" in body, body
    assert set(body["kinds"]) == {"web_app", "api", "repo"}, body["kinds"]


def test_scanners_catalog_repo_kind_has_four_scanners_with_gitleaks_default(
    api_client: httpx.Client,
) -> None:
    """repo: gitleaks (default) + semgrep + osv-scanner + trivy.
    No scan profiles (every code scanner is PASSIVE-only).
    """
    body = api_client.get("/api/v1/scanners").json()
    repo = body["kinds"]["repo"]

    names = {entry["name"] for entry in repo["scanners"]}
    assert names == {"gitleaks", "semgrep", "osv-scanner", "trivy"}, names

    # Default first in the rendered order so a UI rendering
    # top-to-bottom honours the implicit choice.
    assert repo["scanners"][0]["name"] == "gitleaks"
    assert repo["scanners"][0]["is_default"] is True

    # Exactly one default per kind.
    defaults = [e for e in repo["scanners"] if e["is_default"]]
    assert len(defaults) == 1, repo

    # No scan profiles for kind=repo.
    assert repo["scan_profiles"] == [], repo


def test_scanners_catalog_web_app_and_api_have_zap_with_three_profiles(
    api_client: httpx.Client,
) -> None:
    """web_app + api: ZAP only, with the three ScanProfile values."""
    body = api_client.get("/api/v1/scanners").json()
    expected_profiles = ["PASSIVE", "SAFE_ACTIVE", "AGGRESSIVE"]

    for kind in ("web_app", "api"):
        block = body["kinds"][kind]
        assert [e["name"] for e in block["scanners"]] == ["zap"], (kind, block)
        assert block["scanners"][0]["is_default"] is True, (kind, block)
        assert block["scan_profiles"] == expected_profiles, (kind, block)
