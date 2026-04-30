"""Semgrep SAST plugin — Phase 3 Sprint 2.

Sibling of :mod:`zynksec_scanners.gitleaks`.  Static-analysis
rather than secret detection — runs the upstream ``semgrep`` CLI
against a cloned repo with the curated ``p/security-audit``
ruleset.

Findings land in the same :class:`zynksec_db.CodeFinding` table
as gitleaks output.  Sprint 2's migration relaxed
``secret_kind`` and ``secret_hash`` to nullable so Semgrep rows
can omit them honestly (SAST patterns aren't secrets).
"""

from zynksec_scanners.semgrep.plugin import SemgrepPlugin, code_findings_from_semgrep

__all__ = ["SemgrepPlugin", "code_findings_from_semgrep"]
