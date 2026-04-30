"""Semgrep plant — subprocess.run with shell=True."""

import subprocess


def run_cmd(cmd: str) -> subprocess.CompletedProcess:
    # Semgrep's ``subprocess-shell-true`` rule (ERROR) flags
    # ``shell=True`` because ``cmd`` substitution at the shell
    # layer is a command-injection vector when ``cmd`` is
    # user-controlled.  Real code should use list-form invocation.
    return subprocess.run(  # noqa: S602 — intentional Semgrep plant
        cmd,
        shell=True,
        capture_output=True,
    )
