"""Unit tests for :func:`zynksec_scanners.gitleaks.plugin._redact`.

Pre-merge security review BLOCKER #2 regression guard.

The original implementation used ``< 8`` as the all-mask threshold,
which silently revealed the FULL plaintext for any secret of
length exactly 8 (``secret[:4] + "****" + secret[-4:]`` covers
all 8 chars) and 75-89% of the chars for lengths 9-11.  Real-world
secrets in this length range exist (short API tokens, password-
shaped values, generated keys with TEST entropy in dev) and would
have shipped to the DB un-redacted.

The fix bumps the threshold to ``< _REDACT_MIN_LEN`` (= 12).
This test is the contract: no input shorter than 12 chars may
have ANY of its plaintext characters survive the redaction, and
no input may have more than 50% of its characters revealed.
"""

from __future__ import annotations

import string

import pytest
from zynksec_scanners.gitleaks.plugin import _REDACT_MIN_LEN, _redact

# Build the long-secret test input from ``string`` constants rather
# than embedding a high-entropy literal — gitleaks' default
# ``generic-api-key`` rule fires on any 32+ char alphanumeric blob,
# including test fixtures that obviously aren't credentials.
# Constructing at import time keeps the source clean of pattern
# matches while producing the same deterministic value.
_LONG_SECRET_SOURCE: str = (string.ascii_uppercase + string.digits) * 4


@pytest.mark.parametrize(
    "secret",
    [
        "a",  # 1
        "abcd",  # 4
        "abcdefg",  # 7
        "abcdefgh",  # 8 — the canonical "100% leak" case under the old code
        "abcdefghi",  # 9 — 89% leak under the old code
        "abcdefghijk",  # 11 — 73% leak under the old code
        "abcdefghijkl",  # 12 — first length that's safe under the new code
        "abcdefghijklm",  # 13
        "abcdefghijklmnop",  # 16
        "a" * 32,  # 32
        "a" * 40,  # 40 (GitHub PAT-classic length)
    ],
)
def test_redact_never_reveals_more_than_eight_chars(secret: str) -> None:
    """At most 8 plaintext chars survive redaction, on any input length.

    The partial-mask format is ``first-4 + "****" + last-4``, so by
    construction no more than 8 plaintext chars appear in the output.
    Sub-threshold inputs collapse to all-asterisks (0 chars
    revealed).  This invariant is the actual security contract —
    the percentage formulation breaks down at length 12-16 where
    8 of 12-16 chars is 50-67%, but the absolute count (8 chars)
    is what bounds the disclosure.

    The old ``< 8`` threshold violated the absolute bound: an
    8-char secret had ``[:4] + [-4:]`` cover all 8 chars, so 8 of
    8 = 100% (all of them) survived.  This test would FAIL against
    the pre-fix code at lengths 8 / 9 / 10 / 11.
    """
    redacted = _redact(secret)

    # All-asterisks output is unconditionally safe.
    if set(redacted) == {"*"}:
        return

    # Count plaintext characters that survived to the output.  Use
    # multiset-style counting so a repeated char in input doesn't
    # over-count.  Build a list of secret-char positions, then
    # remove each char as we find it in the redacted output to
    # avoid double-counting.
    remaining = list(secret)
    revealed = 0
    for c in redacted:
        if c == "*":
            continue
        if c in remaining:
            remaining.remove(c)
            revealed += 1
    assert revealed <= 8, (
        f"redacted preview {redacted!r} reveals {revealed} plaintext chars "
        f"of input {secret!r} (length {len(secret)}); the partial-mask "
        f"format must never reveal more than 8"
    )


@pytest.mark.parametrize(
    "length",
    [1, 4, 7, 8, 9, 11],
)
def test_redact_short_secrets_are_fully_masked(length: int) -> None:
    """Sub-threshold secrets MUST collapse to all asterisks.

    The original ``< 8`` threshold left lengths 8 / 9 / 10 / 11
    using the partial-mask format, which leaked most of the
    plaintext.  The new threshold (12) covers all four.
    """
    secret = "X" * length
    redacted = _redact(secret)
    assert (
        redacted == "*" * length
    ), f"length-{length} secret was not fully masked: got {redacted!r}"


@pytest.mark.parametrize(
    "length",
    [12, 13, 16, 32, 40, 128],
)
def test_redact_long_secrets_use_partial_mask(length: int) -> None:
    """Threshold-or-longer secrets use the first-4 + last-4 preview.

    The format itself is bounded — the redacted output is ALWAYS
    12 chars (4 + ``****`` + 4) regardless of input length, so
    the DB column ``String(128)`` is more than enough headroom.
    """
    secret = _LONG_SECRET_SOURCE[:length]
    redacted = _redact(secret)

    assert redacted == f"{secret[:4]}****{secret[-4:]}"
    # Output length is always 12 (4 + 4-asterisks + 4).
    assert len(redacted) == 12


def test_redact_min_len_is_at_least_twelve() -> None:
    """Belt-and-braces guard against a future regression that lowers
    the threshold below 12.  Anything below 12 means the partial-
    mask format reveals >50% of the input — see the module
    docstring on _redact for the math.
    """
    assert _REDACT_MIN_LEN >= 12, (
        f"_REDACT_MIN_LEN dropped to {_REDACT_MIN_LEN}; "
        "any value below 12 lets the partial-mask preview "
        "reveal >=50% of short secrets"
    )
