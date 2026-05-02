"""OSV-Scanner dependency-vulnerability plugin — Phase 3 Sprint 3.

Sibling of :mod:`zynksec_scanners.gitleaks` and
:mod:`zynksec_scanners.semgrep`.  Reads package lockfiles
(``package-lock.json``, ``Pipfile.lock``, ``Cargo.lock``,
``go.sum``, ...), queries OSV.dev for known CVEs / GHSAs,
emits one :class:`zynksec_db.CodeFinding` row per
(package, vulnerability) pair.

NETWORK REQUIREMENT: this scanner makes outbound HTTPS calls
to ``api.osv.dev`` for every package found in the lockfile.
Code workers running in a network-isolated environment
(no internet) will surface a clear "OSV API unreachable"
failure rather than producing false-clean results.
"""

from zynksec_scanners.osv.plugin import OsvScannerPlugin, code_findings_from_osv

__all__ = ["OsvScannerPlugin", "code_findings_from_osv"]
