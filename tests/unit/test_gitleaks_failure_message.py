"""Unit test for the gitleaks failure-message scrubbing.

Pre-merge security review FINDING #5 regression guard.

When gitleaks exits with a non-success / non-finding code (i.e.
not 0 and not 1 — typically 2+ on a real crash), the plugin used
to extract ``stderr.splitlines()[-1]`` and embed it in the
``RuntimeError`` message.  That tail then propagated through:

  RuntimeError -> str(exc) -> _execution.execute_scan's outer except
    -> ScanRepository.mark_failed(reason=str(exc))
    -> persisted on Scan.failure_reason
    -> returned in GET /api/v1/scans/{id}

Some gitleaks debug paths print matched-line excerpts to stderr
on crash, which would mean plaintext secrets in the DB and the
public API response.

Fix: the plugin now raises a generic
``RuntimeError("gitleaks exited with code N")`` and logs the
full stderr at debug level (where it can be scrubbed by the
structlog pipeline if needed, and never persisted).

Test strategy: monkeypatch ``subprocess.run`` so the gitleaks
invocation returns a fake non-success CompletedProcess with a
plaintext-secret-shaped stderr.  Construct a minimal Plugin +
ScanContext, call ``run``, catch the RuntimeError, and assert
the secret string does NOT appear anywhere in the exception
chain.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest
from zynksec_scanners.gitleaks.plugin import GitleaksPlugin
from zynksec_scanners.types import (
    RawScanResult,  # noqa: F401 — referenced in test docstring context
    ScanContext,
    ScanProfile,
    ScanTarget,
)

_PLAINTEXT_BAIT = "AKIAREALTESTBAIT01234567"
"""A plausible-looking secret for the synthetic stderr.

Format-valid for gitleaks' ``aws-access-token`` rule (AKIA + 16
chars) so a future regression that mistakenly DOES emit this
string in the failure path would be flagged by gitleaks itself
on the test run.  The test asserts the EXCEPTION never carries
it; the static-analysis layer is independent.
"""


class _FakeHandle:
    """Minimal RepoHandle stand-in — only ``path`` is touched."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.git_url = "https://github.com/synthetic/repo.git"


def test_run_failure_message_does_not_leak_stderr_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Synthetic non-success exit with plaintext stderr → generic message.

    Pre-fix: ``RuntimeError("gitleaks failed: <last stderr line>")``.
    Post-fix: ``RuntimeError("gitleaks exited with code N")``.

    The assertion is on the exception's str() and chained-cause
    chain — neither must contain the plaintext bait.
    """
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    plugin = GitleaksPlugin(gitleaks_bin="/usr/bin/true")  # any non-empty path
    plugin._handle = _FakeHandle(repo_dir)  # type: ignore[assignment]

    fake_completed = subprocess.CompletedProcess(
        args=["gitleaks", "detect"],
        returncode=2,  # NOT 0 or 1 — triggers the failure branch
        stdout="",
        stderr=(
            "gitleaks crashed mid-scan; partial output below\n"
            f"matched value: {_PLAINTEXT_BAIT}\n"
            "stack trace truncated"
        ),
    )

    def _fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return fake_completed

    monkeypatch.setattr(
        "zynksec_scanners.gitleaks.plugin.subprocess.run",
        _fake_run,
    )

    target = ScanTarget(
        kind="repo",
        url="https://github.com/synthetic/repo.git",
        project_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        scan_profile=ScanProfile.PASSIVE,
    )
    context = ScanContext(target=target)

    with pytest.raises(RuntimeError) as exc_info:
        plugin.run(context)

    # The exception message must be the generic exit-code form,
    # not the pre-fix "gitleaks failed: <stderr-tail>" leak path.
    msg = str(exc_info.value)
    assert "gitleaks exited with code" in msg, msg
    assert _PLAINTEXT_BAIT not in msg, f"plaintext bait leaked into RuntimeError message: {msg!r}"

    # Walk the chained-cause chain — if a future regression uses
    # ``raise ... from exc`` to wrap CalledProcessError, the chain
    # might still leak via __cause__.__repr__().
    chained = exc_info.value
    while chained is not None:
        rendered = repr(chained)
        assert (
            _PLAINTEXT_BAIT not in rendered
        ), f"plaintext bait leaked into chained exception: {rendered!r}"
        chained = chained.__cause__ or chained.__context__
        # ``__context__`` chains form on every exception inside an
        # ``except``; bound the walk so we don't loop on cycles.
        if chained is exc_info.value:
            break
