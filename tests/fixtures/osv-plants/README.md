# OSV-Scanner integration plants

Phase 3 Sprint 3. Lockfile-shaped plants for the OSV-Scanner
integration suite (`tests/integration/test_osv_scan.py`).

## What's here

- `package.json` — declares a single dependency on
  `lodash@4.17.20`.
- `package-lock.json` — npm v3 lockfile pinning the same.

## Why lodash@4.17.20

`lodash@4.17.20` carries a stable cluster of advisories that
osv-scanner reliably surfaces (snapshot 2026-04, will only grow):

- **GHSA-35jh-r3h4-6jhm** / CVE-2021-23337 — command injection in
  `template` (CVSS 7.2, **high**), fixed in `4.17.21`.
- **GHSA-29mw-wpgm-hmr9** — ReDoS in `template` (CVSS 5.3,
  **medium**), fixed in `4.17.21`.
- **GHSA-f23m-r3pf-42rh**, **GHSA-r5fr-rjxr-66jc**,
  **GHSA-xxjr-mmjv-4gpg** — additional prototype-pollution and
  hardening advisories (medium / low).

The integration test asserts the scan returns **at least one
high-severity finding** for `GHSA-35jh-r3h4-6jhm` so future
upstream additions don't break the suite. The redacted-preview
check (`lodash@4.17.20 → 4.17.21`) is stable across runs since
both medium / high template advisories share the `4.17.21` fix.

The version was chosen for advisory diversity (different severity
buckets in one package) so a single fixture exercises both the
"high" and "medium" branches of `_classify_severity`.

## Why these stay out of the secret-style assembly dance

Unlike the gitleaks plants (which need split-prefix + base64
construction in `gitfixture.Dockerfile` to avoid tripping
gitleaks / GitHub push protection on the repo's own source),
lockfile entries are not pattern-matched secrets. We commit
them as plain files and `COPY` the whole directory into the
fixture's working tree at image-build time.

## Maintenance

If npm ever revokes the advisory metadata for `lodash@4.17.20`
(unlikely — OSV mirrors the GHSA records permanently), bump to
the next reliably-vulnerable version and update the test
assertion in `test_osv_scan.py`.
