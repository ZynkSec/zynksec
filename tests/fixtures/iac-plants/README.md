# Trivy IaC misconfiguration plants

Phase 3 Sprint 4. Deliberately-misconfigured IaC files for the
Trivy integration suite (`tests/integration/test_trivy_scan.py`).

## What's here

- `Dockerfile.bad` — minimal Dockerfile that fires three Trivy
  Dockerfile rules: `DS-0001` (`:latest` tag, MEDIUM),
  `DS-0002` (`USER root`, HIGH), `DS-0026` (no `HEALTHCHECK`,
  LOW). The `.bad` suffix keeps the file from accidentally
  being picked up by other Dockerfile-discovery tooling.
- `pod.yaml` — minimal Kubernetes Pod manifest. Fires the
  whole privileged-container cluster: `KSV-0017` (privileged,
  HIGH), `KSV-0014` (root file system not read-only, HIGH),
  `KSV-0012` (runs as root, MEDIUM), plus 15+ default-namespace
  / missing-resource-limit / capability rules.

## Why these rule IDs

Trivy 0.70+ uses the dashed format `DS-0001` / `KSV-0017` (older
versions used `DS001` / `KSV001`). The integration test pins
both the dashed IDs **and** asserts at least one HIGH severity
finding lands in `code_findings`, so a future Trivy bump that
re-renames rule IDs will surface as a clear test failure.

## Why these stay under tests/fixtures/

The Trivy CI step at `.github/workflows/ci.yml` already skips
`tests/fixtures/` (added during the Sprint 3 OSV-Scanner work).
Putting these IaC plants anywhere else would make the
production-security CI flag our own test material as a real
finding — same lesson as Sprint 1's gitleaks-vs-fixture tension.

## Why no Terraform / Helm / CloudFormation

Two engines (Dockerfile + Kubernetes) is enough to exercise the
plugin's rule-id parsing, severity mapping, and `StartLine`
extraction across distinct misconfig families. Adding more
engines would just balloon the integration test runtime
without exercising new code paths in `TrivyPlugin`.
