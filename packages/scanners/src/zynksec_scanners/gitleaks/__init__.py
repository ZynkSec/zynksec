"""Gitleaks scanner plugin — Phase 3 Sprint 1.

First repo-scanner family alongside the ZAP DAST plugin.  Detects
secrets committed to source code (AWS keys, GitHub PATs, Slack
webhooks, ...) by shelling out to the upstream gitleaks CLI.

Hard rule: plaintext secrets NEVER touch the database.  The plugin
strips the raw match value before constructing :class:`CodeFinding`
rows; what is persisted is :attr:`CodeFinding.redacted_preview`
plus :attr:`CodeFinding.secret_hash` (SHA-256).  See
``packages/db/.../models/code_finding.py`` for the security
contract.
"""

from zynksec_scanners.gitleaks.plugin import GitleaksPlugin

__all__ = ["GitleaksPlugin"]
