# Pinned by digest. Bump via Dependabot or manual checksum re-verification.
#
# gitfixture — serves a known-vulnerable bare git repo over smart
# HTTP for the Phase 3 Sprint 1 integration tests.  Builds the bare
# repo at image-build time (deterministic plants) and serves it via
# a tiny smart-HTTP wrapper around ``git-http-backend`` (CGI).  Smart
# HTTP is required because the cloner uses ``git clone --depth 1`` —
# dumb HTTP errors out with ``shallow capabilities`` not advertised.
#
# Lives under ``tests/fixtures/`` because it is exclusively a test
# concern.  Brought up as the ``gitfixture`` service in
# ``tests/integration/docker-compose.test.yml``.
#
# IMPORTANT: the planted "secret" values are CONSTRUCTED inside this
# Dockerfile from split / base64-encoded fragments (never as
# contiguous literals).  GitHub push protection + most secret
# scanners scan files for the canonical AKIA / ghp_ / Slack-webhook
# patterns — committing the assembled plants directly would block
# the push even though the values are synthetic.  Splitting + base64
# keeps the source clean of pattern-matched strings while the image
# build assembles them locally.  None of the values below are real
# credentials; the entropy substring is literally "TEST" / "EXAMPLE".
#
# Phase 3 Sprint 2 adds Semgrep plants: short Python files in
# ``tests/fixtures/semgrep-plants/`` (eval, shell=True, pickle.loads
# patterns) committed as plain source.  Unlike the gitleaks plants,
# Semgrep patterns aren't secret-shaped so GitHub secret scanning
# / gitleaks both ignore them — no fragment-construction needed.
# The runtime stage ``COPY``s the whole directory into the bare
# repo so a single ``git clone`` carries both gitleaks plants AND
# Semgrep plants in one tree.

# Base image pinned by digest (Phase 3 cleanup item #2).  Tag stays
# in the comment for legibility but ``@sha256:`` is the load-bearing
# identifier.  Same digest used in both stages below.
FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS builder

# git for the repo bootstrap.  Use debian:bookworm-slim instead of
# alpine because the runtime image needs the same ``git-http-backend``
# binary path layout — sticking with debian on both sides keeps the
# CGI wrapper's hardcoded path correct without a per-distro switch.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/src

# Plant assembly.  Each rule uses a shell technique that keeps the
# matched pattern from appearing as a contiguous literal in any file
# committed to this repo:
#
#   1. AWS access key — concatenate ``AKIA`` + the suffix in shell.
#      The single line ``aws_access_key_id=AKIA...`` only exists on
#      the runtime container's filesystem, never in the Dockerfile
#      tokens git stores.
#   2. GitHub PAT — same split-prefix technique with ``ghp_``.
#   3. Slack webhook — base64-decode an opaque blob.
#
# Comment lines in each plant file pad to line 5, where the actual
# matched value sits — the integration test asserts ``line_number==5``.
RUN mkdir -p config secrets webhooks \
 && AWS_PREFIX="AKIA" \
 && AWS_SUFFIX="IOSFODNN7TESTKEY" \
 && { \
        echo "# Test plant for the gitleaks integration suite."; \
        echo "# Format-valid AWS access-key id with TEST entropy in the suffix."; \
        echo "# The gitleaks rule ``aws-access-token`` matches the prefix +"; \
        echo "# 16 uppercase-alphanumeric chars.  Not a real key."; \
        echo "aws_access_key_id=${AWS_PREFIX}${AWS_SUFFIX}"; \
    } > config/aws_credentials.txt \
 && GH_PREFIX="ghp_" \
 && GH_SUFFIX="TESTONLYNOTREALabcdefghijKLMNOPQRSTU" \
 && { \
        echo "# Test plant for the gitleaks integration suite."; \
        echo "# Format-valid GitHub personal-access-token (classic) — gitleaks"; \
        echo "# rule ``github-pat`` matches the prefix + 36 alphanumeric chars."; \
        echo "# Not a real token."; \
        echo "github_token=${GH_PREFIX}${GH_SUFFIX}"; \
    } > secrets/github_token.txt \
 && SLACK_VALUE="$(echo aHR0cHM6Ly9ob29rcy5zbGFjay5jb20vc2VydmljZXMvVFRFU1RPTkxZMDAwMDAwMDAvQlRFU1RPTkxZMDAwMDAvYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4 | base64 -d)" \
 && { \
        echo "# Test plant for the gitleaks integration suite."; \
        echo "# Format-valid Slack webhook URL — gitleaks rule"; \
        echo "# ``slack-webhook-url`` matches the canonical hooks.slack.com"; \
        echo "# path shape.  Not a real webhook."; \
        echo "slack_webhook: ${SLACK_VALUE}"; \
    } > webhooks/slack.yaml \
 && cat > app.py <<'PY'
"""Empty placeholder so the fixture repo carries a non-secret file too.

Some scanners (and some tests) want to confirm the scan pulled the
whole working tree — a "boring" file proves the cloner didn't
accidentally fetch only files matching ``*secret*``.
"""

print("hello from the vulnerable-repo fixture")
PY

# Phase 3 Sprint 2: copy the Semgrep plant files into the working
# tree alongside the gitleaks plants.  The integration tests
# (``test_semgrep_scan.py``) assert that gitleaks scans see only
# the gitleaks plants (3 secrets) and Semgrep scans see only the
# Semgrep plants (3 SAST findings) — both sets live in the same
# bare repo, the scanner family is what differentiates.
COPY tests/fixtures/semgrep-plants/ /tmp/src/semgrep-plants/

# Initialise + commit the working tree, then turn it into a bare
# repo.  Synthetic ``zynksec-fixture`` author identity makes it
# obvious the commits are not from a real maintainer.
RUN git -c init.defaultBranch=main init -q . \
 && git config user.email "fixture@zynksec.test" \
 && git config user.name "zynksec-fixture" \
 && git config commit.gpgsign false \
 && git add . \
 && git commit -q -m "phase 3 sprint 2 vulnerable-repo fixture" \
 && git clone -q --bare /tmp/src /srv/vulnerable-repo.git

# Runtime: debian:bookworm-slim with python3 + git (for
# git-http-backend).  Slightly bigger than alpine but the
# git-http-backend binary path matches what
# ``gitfixture-server.py`` expects.  Same digest pin as the
# builder stage.
FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends python3 git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /srv/vulnerable-repo.git /srv/vulnerable-repo.git
COPY tests/fixtures/gitfixture-server.py /usr/local/bin/gitfixture-server.py

EXPOSE 80

# Smart-HTTP server.  Routes every request through git-http-backend
# (CGI) so ``git clone --depth 1`` works.  The wrapper's
# ``GIT_PROJECT_ROOT=/srv`` makes the bare-repo dir name
# (``vulnerable-repo.git``) the URL path component — clients reach
# it as ``http://gitfixture/vulnerable-repo.git``.
CMD ["python3", "/usr/local/bin/gitfixture-server.py"]
