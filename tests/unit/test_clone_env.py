"""Unit tests for :func:`zynksec_scanners.repo.cloner._build_clone_env`.

Phase 3 Sprint 1 cleanup item #4 regression guard.

The pre-cleanup cloner built the env as a hardcoded 3-key dict
(``GIT_TERMINAL_PROMPT``, ``PATH``, ``HOME``).  That meant:

  * Corporate-proxy operators couldn't reach github via
    ``HTTPS_PROXY`` — the var was silently dropped on the way
    into the subprocess.
  * Custom CA bundles (``SSL_CERT_FILE``, ``GIT_SSL_CAINFO``)
    didn't reach the libcurl layer git uses for HTTPS, so an
    on-prem GitLab with a private CA would fail TLS verification
    rather than honour operator config.

The fix forwards a curated allow-list of env-var prefixes
(``GIT_``, ``HTTPS_``, ``HTTP_``, ``NO_``, ``SSL_``) AND keeps
the explicit zynksec overrides on top.  This test pins the
contract: each prefix is forwarded, unrelated parent env is
NOT, and the explicit overrides win when keys collide.
"""

from __future__ import annotations

import pytest
from zynksec_scanners.repo.cloner import _build_clone_env


def test_clone_env_forwards_inherited_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every var matching the prefix allow-list is forwarded.

    ``HTTPS_PROXY`` (proxy config), ``SSL_CERT_FILE`` (custom CA),
    ``GIT_SSL_CAINFO`` (per-git CA override) all need to reach
    the subprocess.
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.corp:8080")
    monkeypatch.setenv("NO_PROXY", "internal.example.com")
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/custom-bundle.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/etc/ssl/certs.d")
    monkeypatch.setenv("GIT_SSL_CAINFO", "/etc/ssl/git-bundle.pem")
    monkeypatch.setenv("GIT_CURL_VERBOSE", "1")

    env = _build_clone_env()

    assert env["HTTPS_PROXY"] == "http://proxy.corp:8080"
    assert env["HTTP_PROXY"] == "http://proxy.corp:8080"
    assert env["NO_PROXY"] == "internal.example.com"
    assert env["SSL_CERT_FILE"] == "/etc/ssl/custom-bundle.pem"
    assert env["SSL_CERT_DIR"] == "/etc/ssl/certs.d"
    assert env["GIT_SSL_CAINFO"] == "/etc/ssl/git-bundle.pem"
    assert env["GIT_CURL_VERBOSE"] == "1"


def test_clone_env_drops_non_allowlisted_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Variables NOT on the allow-list must not leak into the subprocess.

    A few representative cases: ``LD_PRELOAD`` (process-injection
    surface), ``PYTHONPATH`` (irrelevant to git but could change
    behaviour if git wrappers exist on PATH), ``DATABASE_URL``
    (project-scoped secret, definitely no reason for git to see
    it).
    """
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")  # noqa: S108 — synthetic test value
    monkeypatch.setenv("PYTHONPATH", "/some/import/path")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db/zynksec")
    monkeypatch.setenv("CELERY_BROKER_URL", "redis://redis:6379/0")

    env = _build_clone_env()

    assert "LD_PRELOAD" not in env
    assert "PYTHONPATH" not in env
    assert "DATABASE_URL" not in env
    assert "CELERY_BROKER_URL" not in env


def test_clone_env_explicit_overrides_win_on_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An operator-supplied ``GIT_TERMINAL_PROMPT=1`` must NOT win.

    The cloner's explicit override forces ``GIT_TERMINAL_PROMPT=0``
    so a pathological operator env can't accidentally re-enable
    interactive credential prompts.
    """
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "1")  # operator tries to enable
    env = _build_clone_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_clone_env_always_includes_path_and_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with a sparse parent env, ``PATH`` and ``HOME`` are populated."""
    # Clear the relevant vars to verify the function provides
    # defaults via ``os.environ.get(default=...)``.
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")

    env = _build_clone_env()
    assert env["PATH"] == "/usr/local/bin:/usr/bin"
    assert env["HOME"]  # non-empty default
