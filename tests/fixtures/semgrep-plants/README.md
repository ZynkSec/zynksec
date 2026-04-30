# Semgrep plants for the gitfixture

Phase 3 Sprint 2 fixtures for the SemgrepPlugin integration test
suite. Three short Python files with intentional patterns that
the upstream `p/security-audit` ruleset matches:

| File               | Rule                                                                     | Severity         |
| ------------------ | ------------------------------------------------------------------------ | ---------------- |
| `eval_handler.py`  | `python.lang.security.audit.eval-detected.eval-detected`                 | WARNING (medium) |
| `shell_runner.py`  | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` | ERROR (high)     |
| `pickle_loader.py` | `python.lang.security.deserialization.pickle.avoid-pickle`               | WARNING (medium) |

Unlike the gitleaks plants (constructed in
`gitfixture.Dockerfile` from split fragments to dodge GitHub
secret scanning), these Semgrep plants are committed as plain
source — none of them match secret-shaped patterns, so gitleaks
ignores them and GitHub push protection lets them through.

The `gitfixture.Dockerfile` `COPY`s this whole directory into
`/tmp/src/` at image-build time so the bare repo carries both
gitleaks and Semgrep plants in one tree. Integration test
`test_semgrep_scan_finds_planted_vulnerabilities` (in
`tests/integration/test_semgrep_scan.py`) asserts each rule
fires on the expected file + line.
