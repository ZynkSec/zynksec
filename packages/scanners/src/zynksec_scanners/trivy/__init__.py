"""Trivy IaC misconfiguration plugin — Phase 3 Sprint 4.

Sibling of :mod:`zynksec_scanners.gitleaks`,
:mod:`zynksec_scanners.semgrep`, and
:mod:`zynksec_scanners.osv`.  Scans Dockerfiles, Kubernetes
manifests, Terraform, Helm charts, and CloudFormation for
misconfigurations (privileged containers, root users, missing
healthchecks, public storage, etc.).

OFFLINE BY DESIGN: this scanner uses Trivy in misconfig-only
mode with ``--skip-policy-update --skip-db-update --offline-scan``
so it makes NO outbound network calls at scan time.  The
misconfig policies ship bundled in the binary itself.  This is
both a security property (no opportunity for upstream tampering
mid-scan) and a reliability property (works in air-gapped
environments).

Trivy can ALSO scan for vulnerabilities (overlap with OSV-Scanner)
and secrets (overlap with Gitleaks); we explicitly avoid both
modes here.  A future ``trivy-vuln`` / ``trivy-secrets`` family
would register as separate scanners if ever wanted.
"""

from zynksec_scanners.trivy.plugin import TrivyPlugin, code_findings_from_trivy

__all__ = ["TrivyPlugin", "code_findings_from_trivy"]
