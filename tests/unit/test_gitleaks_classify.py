"""Unit tests for :func:`zynksec_scanners.gitleaks.plugin._classify`.

Phase 3 Sprint 1 cleanup item #8 regression guard.

The pre-cleanup classifier had three loose-prefix entries:
``("jwt",)``, ``("oauth",)``, ``("api-key",)``.  These would
match ``jwt-token`` (intended) AND any future rule whose name
started with "jwt" (``jwtbomb``, ``jwt-anything``).  Other
entries used the trailing-dash convention; these three didn't.

Fix: split the matching table into:

  * ``_SEVERITY_BY_EXACT_RULE`` for canonical bare-name rules
    (``jwt``, ``private-key``, ``rsa-private-key``,
    ``generic-api-key``) — matched with ``==``.
  * ``_SEVERITY_BY_RULE_PREFIX`` for family prefixes — every
    entry now requires a trailing dash.

This test pins the contract: exact-name rules return their
exact mapping; family-prefix rules match the ``family-`` form
ONLY when followed by SOMETHING (not the bare family); unknown
rules fall through to ``("Unclassified secret", "low")``.
"""

from __future__ import annotations

import pytest
from zynksec_scanners.gitleaks.plugin import _classify


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        # Exact-match rules from upstream gitleaks default config.
        ("jwt", ("Bearer / OAuth token", "medium")),
        ("private-key", ("Private key material", "critical")),
        ("rsa-private-key", ("Private key material", "critical")),
        ("generic-api-key", ("Generic API key", "medium")),
        # Case-insensitivity.
        ("JWT", ("Bearer / OAuth token", "medium")),
        ("Generic-API-Key", ("Generic API key", "medium")),
    ],
)
def test_classify_exact_match(rule_id: str, expected: tuple[str, str]) -> None:
    """Bare-name rules use exact-match against
    :data:`_SEVERITY_BY_EXACT_RULE`."""
    assert _classify(rule_id) == expected


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        # Real gitleaks default rule names — must still classify.
        ("aws-access-token", ("AWS access key", "critical")),
        ("aws-secret-key", ("AWS access key", "critical")),
        ("github-pat", ("Source-host personal access token", "high")),
        ("gitlab-pat", ("Source-host personal access token", "high")),
        ("slack-webhook-url", ("Third-party API key (production-scope)", "high")),
        ("stripe-access-token", ("Third-party API key (production-scope)", "high")),
        ("gcp-service-account", ("GCP service-account credential", "critical")),
        # Family-prefix rules with the trailing dash present.
        ("jwt-base64", ("Bearer / OAuth token", "medium")),
        ("oauth-pat", ("Bearer / OAuth token", "medium")),
    ],
)
def test_classify_dashed_family_prefix(rule_id: str, expected: tuple[str, str]) -> None:
    """``family-`` prefix matches any ``family-X`` rule."""
    assert _classify(rule_id) == expected


@pytest.mark.parametrize(
    "rule_id",
    [
        # Hypothetical future rules whose names BEGIN with a
        # family token but lack the trailing dash.  Pre-cleanup,
        # the loose ``startswith("jwt")`` would match these and
        # mis-classify them as JWTs.  Post-cleanup, they fall
        # through to the unclassified bucket so an operator
        # notices the new rule.
        "jwtbomb",  # would have matched startswith("jwt") pre-fix
        "oauthlike-thing",  # would have matched startswith("oauth")
        "api-keyless",  # would have matched startswith("api-key")
        "awsome-not-aws",  # would have matched startswith("aws-")? No, no dash
        # Future / unknown gitleaks rules.
        "telegram-bot-token",
        "discord-api-token",
    ],
)
def test_classify_unknown_falls_through_to_low(rule_id: str) -> None:
    """Rules outside the curated mapping go to "Unclassified secret"
    at low severity — visible to operators (so they can update the
    mapping) without drowning out high-confidence AWS / GCP / etc.
    findings.
    """
    kind, severity = _classify(rule_id)
    assert kind == "Unclassified secret"
    assert severity == "low"


def test_classify_jwt_does_not_match_jwtbomb() -> None:
    """Direct contract test for the cleanup-item #8 regression.

    Pre-cleanup: ``"jwtbomb".startswith("jwt")`` was True →
    classified as Bearer/OAuth token at medium severity.

    Post-cleanup: the family table requires ``jwt-`` (with dash);
    the exact table only accepts ``"jwt"`` exactly.  ``jwtbomb``
    matches neither and falls through to unclassified/low.
    """
    assert _classify("jwt") == ("Bearer / OAuth token", "medium")
    assert _classify("jwtbomb") == ("Unclassified secret", "low")
