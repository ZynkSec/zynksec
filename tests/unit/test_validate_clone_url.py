"""Unit tests for :func:`zynksec_scanners.repo.cloner.validate_clone_url`.

Pre-merge security review BLOCKER #4 regression guard.

The pre-fix validator accepted URLs containing control characters
(``\\n``, ``\\r``, ``\\t``, ``\\0``), percent-encoded null bytes
(``%00``), path-traversal segments (``..``), and raw IP-literal
hosts (``127.0.0.1``, ``169.254.169.254``, RFC1918, IPv6
loopback).  List-form ``subprocess.run`` blocks shell injection,
but log-injection via ``\\n`` and SSRF via IP-literal hosts were
real attack surfaces.

This test pins the post-fix accept/reject table.  Each case is
parameterized so a regression on any single URL is visible in CI
output without burying the failure under siblings.
"""

from __future__ import annotations

import pytest
from zynksec_scanners.repo.cloner import CloneError, validate_clone_url

# Each entry: (input URL, expected verdict).  ``True`` means accept,
# ``False`` means reject.  Test names render the URL's repr so a
# failure points at the exact case that flipped.
_PROBE_TABLE: list[tuple[str, bool]] = [
    # ---------- Happy paths ----------
    ("https://github.com/owner/repo.git", True),
    ("https://github.com/owner/repo", True),  # no .git suffix
    ("https://gitlab.com/owner/repo.git", True),
    ("https://bitbucket.org/owner/repo.git", True),
    ("https://GITHUB.COM/owner/repo.git", True),  # case-insensitive host
    # ---------- Scheme rejection ----------
    ("http://github.com/owner/repo", False),  # http not in default allow-list
    ("ssh://git@github.com/owner/repo", False),
    ("git://github.com/owner/repo", False),
    ("file:///etc/passwd", False),
    # ---------- Host rejection ----------
    ("https://evil.com/owner/repo.git", False),
    ("https://github.com.evil.com/owner/repo.git", False),  # suffix confusion
    ("https://github.com@evil.com/repo.git", False),  # userinfo abuse
    # ---------- Userinfo rejection ----------
    ("https://token@github.com/owner/repo.git", False),
    ("https://user:pass@github.com/owner/repo.git", False),
    # ---------- BLOCKER #4 — control character rejection ----------
    ("https://github.com/owner/repo.git\necho pwned", False),
    ("https://github.com/owner/repo.git\rinjected", False),
    ("https://github.com/owner/repo.git\tab", False),
    ("https://github.com/owner/repo.git\x00null", False),
    # ---------- BLOCKER #4 — percent-null rejection ----------
    ("https://github.com/owner/repo.git%00.evil.com", False),
    ("https://github.com/owner/repo.git%00", False),
    # ---------- BLOCKER #4 — path traversal rejection ----------
    ("https://github.com/../../../etc/passwd", False),
    ("https://github.com/owner/../../etc/passwd", False),
    # ---------- BLOCKER #4 — IP-literal SSRF rejection ----------
    ("https://localhost/repo.git", False),  # by host allow-list (always was)
    ("https://127.0.0.1/repo.git", False),  # IPv4 loopback
    ("https://169.254.169.254/latest/meta-data", False),  # AWS metadata
    ("https://10.0.0.1/repo.git", False),  # RFC1918 private
    ("https://192.168.1.1/repo.git", False),  # RFC1918 private
    ("https://172.16.0.1/repo.git", False),  # RFC1918 private
    ("https://[::1]/repo.git", False),  # IPv6 loopback
    ("https://[fe80::1]/repo.git", False),  # IPv6 link-local
]


@pytest.mark.parametrize(
    ("url", "expected_accept"),
    _PROBE_TABLE,
    ids=[repr(url) for url, _ in _PROBE_TABLE],
)
def test_validate_clone_url_probe_table(url: str, expected_accept: bool) -> None:
    """The accept/reject verdict for each probe URL must match the table."""
    if expected_accept:
        # Happy path — no exception, returns (scheme, host) tuple.
        scheme, host = validate_clone_url(url)
        assert scheme in {"https", "http"}, scheme
        assert host, host
    else:
        with pytest.raises(CloneError):
            validate_clone_url(url)


def test_validate_clone_url_rejects_overlong_input() -> None:
    """URLs longer than the 2048 char cap are rejected before any other
    check — keeps pathological inputs from reaching urlsplit / git.
    """
    long_path = "x" * 2100
    with pytest.raises(CloneError, match="2048"):
        validate_clone_url(f"https://github.com/{long_path}")


def test_validate_clone_url_message_does_not_echo_url() -> None:
    """Error messages must not echo the offending URL verbatim — it
    could carry a userinfo segment we don't want surfaced.  Spot-check
    a few rejection paths.
    """
    bad_urls_with_secrets = [
        "https://t0kenABCDEF@github.com/owner/repo.git",  # userinfo
        "https://github.com/owner/repo.git\nsecret-data",  # control char
    ]
    for url in bad_urls_with_secrets:
        with pytest.raises(CloneError) as exc_info:
            validate_clone_url(url)
        assert url not in str(
            exc_info.value
        ), f"CloneError message echoed the URL verbatim: {exc_info.value}"
