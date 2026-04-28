# Phase 0 — Foundation Scaffolding

> **Status:** Design — v0.1, 2026-04-22
> **Predecessors:** `01_scoping_and_roadmap.md`, `02_product_strength_and_foundations.md`, `03_architecture.md`
> **Successor:** `05_phase1_dast_mvp.md` (will be written when Phase 0 exits)

## 0.0 Why Phase 0 exists

Before anything resembling a "product" can ship, Zynksec needs a reproducible foundation: a monorepo with clear boundaries, a one-command local environment, a working scanner pipeline end-to-end (even if it only does one thing), and the operational scaffolding (CI, secrets handling, observability) that will be cheap to add now and brutal to add later.

Phase 0 is the **walking skeleton**: the smallest possible vertical slice that exercises every layer of the architecture against a real target. Phase 1 then thickens the slice into an actual MVP.

## 0.1 Goal

> **Get from "empty repo" to: one `docker compose up`, then a `POST /scans` that runs OWASP ZAP against a local OWASP Juice Shop instance, persists normalized findings in PostgreSQL, and returns them on `GET /scans/{id}`.**

That's it. No UI logic. No auth. No multi-scanner orchestration. No prioritization. No correlation. Just the spine.

## 0.2 Definition of Done (exit criteria)

Phase 0 is complete when, on a clean clone:

1. `cp .env.example .env` and `docker compose up` brings up: `api`, `worker`, `postgres`, `redis`, `zap`, `juice-shop`, `mailpit`, `glitchtip` (the last two optional via Compose profiles).
2. `pnpm install && pnpm --filter web dev` starts the Next.js shell on `http://localhost:3000` (it doesn't need to do anything yet — just render and call `/api/health`).
3. `POST http://localhost:8000/scans` with `{"target_url": "http://juice-shop:3000"}` returns a scan ID and the scan transitions through `queued → running → completed` in PostgreSQL.
4. `GET http://localhost:8000/scans/{id}` returns the scan plus a non-empty list of `Finding` records normalized from ZAP's output.
5. `pre-commit run --all-files` is green: Ruff, Black, Prettier, Gitleaks, end-of-file fixer, large-files check.
6. The GitHub Actions CI workflow runs on every PR and is green: Gitleaks, Ruff, Black --check, Prettier --check, ESLint, Trivy filesystem scan, plus a placeholder pytest step that runs zero tests but doesn't fail.
7. Every secret is in `.env.example` (with safe placeholder values) and **no real secret has ever been committed** — verifiable via `git log -p` and a Gitleaks scan of full history.
8. The `README.md` "Quick start" section reflects the actual flow above and a fresh contributor can follow it.

If any of these is "almost true," Phase 0 is not done.

## 0.3 Out of scope for Phase 0

Explicitly deferred to keep Phase 0 tight:

- Authentication and authorization (the API runs unauthenticated locally; this is a planet-killer assumption that gets fixed in Phase 1).
- Ownership verification (DNS TXT / well-known file). Phase 0 only scans `juice-shop` on a private Docker network — there is no public attack surface to misuse.
- Multiple scanners (Nuclei, ProjectDiscovery suite). ZAP only.
- Finding correlation, deduplication beyond fingerprinting, KEV/EPSS enrichment, prioritization heuristics.
- A real frontend. The Next.js app exists as a build target so the monorepo wiring works, not as a usable UI.
- Production deployment. Local Docker Compose only.
- Email transport. Mailpit catches anything; Resend integration waits for Phase 2.
- Multi-tenancy. One implicit "dev" user, one project.

These are not "won't have" — they're "won't have **yet**." Each has a phase pointer in `01_scoping_and_roadmap.md`.

## 0.4 Monorepo layout

```
zynksec/
├── LICENSE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── .gitignore
├── .pre-commit-config.yaml
├── .editorconfig
├── .nvmrc                          # Node version pin
├── .python-version                 # via pyenv (optional but documented)
├── pnpm-workspace.yaml
├── package.json                    # root, dev tooling only (prettier, eslint, husky)
├── pyproject.toml                  # root, workspace tooling (ruff, black, mypy)
├── docker-compose.yml              # canonical local stack
├── docker-compose.override.example.yml
├── .env.example
├── docs/
│   ├── 01_scoping_and_roadmap.md
│   ├── 02_product_strength_and_foundations.md
│   ├── 03_architecture.md
│   └── 04_phase0_scaffolding.md   # this file
├── apps/
│   ├── api/                        # FastAPI service
│   │   ├── pyproject.toml
│   │   ├── Dockerfile
│   │   ├── alembic.ini
│   │   ├── alembic/                # migrations
│   │   └── src/zynksec_api/
│   │       ├── __init__.py
│   │       ├── main.py             # FastAPI app
│   │       ├── config.py           # pydantic-settings
│   │       ├── db.py               # engine + get_session() dependency
│   │       ├── celery_client.py    # enqueue Celery tasks from the API
│   │       ├── exceptions.py       # canonical {code,message,request_id}
│   │       # ORM models live in packages/db/src/zynksec_db/models/
│   │       # (moved out of apps/api in Week 2 so apps/worker can share them)
│   │       ├── routers/            # /scans, /projects, /health
│   │       └── schemas/            # request/response pydantic models
│   ├── worker/                     # Celery worker
│   │   ├── pyproject.toml
│   │   ├── Dockerfile
│   │   └── src/zynksec_worker/
│   │       ├── __init__.py
│   │       ├── celery_app.py
│   │       ├── tasks/
│   │       │   └── scan.py         # the scan.run task
│   │       └── runners/
│   │           └── zap_runner.py   # wraps the ZAP plugin
│   └── web/                        # Next.js frontend (placeholder)
│       ├── package.json
│       ├── next.config.mjs
│       ├── app/
│       │   ├── page.tsx            # "Zynksec — pre-alpha" splash
│       │   └── api/health/route.ts # proxies to backend /health
│       └── tailwind.config.ts
├── packages/
│   ├── shared-schema/              # Python: canonical Finding pydantic models
│   │   ├── pyproject.toml
│   │   └── src/zynksec_schema/
│   │       ├── __init__.py
│   │       └── finding.py          # Finding v1 (Phase 0 subset)
│   ├── db/                         # Python: SQLAlchemy 2.x ORM + repositories
│   │   ├── pyproject.toml          # — shared by apps/api and apps/worker
│   │   └── src/zynksec_db/         #   (added Week 2)
│   │       ├── __init__.py
│   │       ├── base.py             # DeclarativeBase + naming convention
│   │       ├── session.py          # engine_from_url, make_session_factory
│   │       ├── models/             # Project, Scan, Finding
│   │       └── repositories/       # Repository[T], ScanRepository, ...
│   └── scanners/                   # Python: scanner plugin contract + ZAP impl
│       ├── pyproject.toml
│       └── src/zynksec_scanners/
│           ├── __init__.py
│           ├── base.py             # ScannerPlugin abstract base
│           └── zap/
│               ├── __init__.py
│               └── plugin.py
├── infra/
│   ├── docker/
│   │   ├── api.Dockerfile
│   │   ├── worker.Dockerfile
│   │   └── web.Dockerfile
│   └── compose/
│       ├── postgres-init.sql
│       └── zap-config/
├── target-lab/
│   ├── README.md                   # which targets exist, which CVEs they have
│   └── compose-targets.yml         # juice-shop, dvwa, webgoat (only juice-shop in Phase 0)
├── scripts/
│   ├── bootstrap.sh                # idempotent local setup
│   ├── seed.py                     # seeds dev project + target
│   └── scan-juice-shop.sh          # convenience: triggers a scan and tails logs
└── .github/
    ├── workflows/
    │   └── ci.yml
    ├── dependabot.yml              # already added
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.yml
    │   ├── design_review.yml
    │   └── config.yml
    └── pull_request_template.md
```

Two principles drive this layout:

1. **`apps/` are deployable units, `packages/` are libraries.** Anything imported by more than one app lives in `packages/`. The Finding schema is the most important shared package — it's the contract every scanner and every consumer agrees on. ORM models also live in a shared package (`packages/db`) because both `apps/api` and `apps/worker` need them; putting them in `apps/api/src/zynksec_api/models/` would force a cross-app import in the worker, which CLAUDE.md §5 forbids.
2. **`infra/` is "things that build or run the apps,"** not "things the apps import." Dockerfiles, Compose snippets, and init SQL live there. Application code never imports from `infra/`.

## 0.5 Tech choices, restated

These are locked from `03_architecture.md`. Listing them here so this doc stands alone:

| Layer | Choice | Why |
| --- | --- | --- |
| Backend language | Python 3.12 | ZAP, ProjectDiscovery, Semgrep all have first-class Python integration. |
| API framework | FastAPI | Pydantic-native, OpenAPI for free, async-friendly. |
| Background work | Celery + Redis | Mature, well-known operational shape; Hugo can debug it without learning a new mental model. |
| Database | PostgreSQL 16 | Need rich JSONB for evidence + transactional guarantees for finding lifecycle. |
| Migrations | Alembic | Standard with SQLAlchemy. |
| Frontend | Next.js 15 (App Router) + React 19 + Tailwind + shadcn/ui | Aligns with the Next.js + Vercel framework profile we ship first. (Bumped from 14 in Phase 0 Week 1 — two unpatched HIGH advisories in the 14.x line: GHSA-h25m-26qc-wcjf, GHSA-q4gf-8mx6-v5v3.) |
| Frontend pkg manager | pnpm | Disk-efficient and the workspace story is cleanest. |
| DAST engine | OWASP ZAP (Stable) | Locked decision. |
| Local dev | Docker Compose | Single command, no Kubernetes until revenue exists. |
| Error tracking | GlitchTip (self-hosted, optional) | Sentry-compatible SDK, free, runs in Compose. |
| Email (dev) | Mailpit | Catches all SMTP locally, has a UI, zero config. |
| Email (prod) | Resend | Hugo already has an account. Phase 2+. |
| Pre-commit | `pre-commit` (Python) | Polyglot, lots of community hooks. |
| CI | GitHub Actions | Free for public repos. |

## 0.6 Network zones

Three Docker networks, defined in `docker-compose.yml`. No service touches a network it doesn't need.

```
┌──────────────────── zynksec-core ────────────────────┐
│  api  ←→  postgres                                   │
│  api  ←→  redis                                      │
│  api  ←→  glitchtip   (optional, profile: obs)       │
│  worker  ←→  postgres                                │
│  worker  ←→  redis                                   │
│  worker  ←→  glitchtip                               │
└──────────────────────────────────────────────────────┘

┌──────────────────── zynksec-scan ────────────────────┐
│  worker  ←→  zap                                     │
└──────────────────────────────────────────────────────┘

┌──────────────────── zynksec-targets ─────────────────┐
│  zap  ←→  juice-shop                                 │
│  (more targets later: dvwa, webgoat, bWAPP)          │
└──────────────────────────────────────────────────────┘
```

Key rules enforced by the topology:

- **The API never touches scanners or targets.** It enqueues work. That's it. This is the gate that lets us, in Phase 5+, host the API publicly and put scanner workers in a separate VPC.
- **Targets cannot reach the core.** Even if Juice Shop or a future malicious target tries to call back into Zynksec, there's no network path.
- **Workers bridge `core` and `scan`** but cannot reach `targets` directly — only through ZAP. This is the seed of the egress-control story we'll need before any scan touches a public URL.

In Phase 0 these zones are inside one Docker host. The exact same labels carry forward to Phase 5 when scan workers move to a separate VPS.

## 0.7 `docker-compose.yml` service inventory

| Service | Image | Ports (host) | Networks | Profile | Purpose |
| --- | --- | --- | --- | --- | --- |
| `api` | built from `infra/docker/api.Dockerfile` | `8000` | `core` | default | FastAPI app. |
| `worker` | built from `infra/docker/worker.Dockerfile` | — | `core`, `scan` | default | Celery worker, runs scan tasks. |
| `postgres` | `postgres:16-alpine` | — (internal) | `core` | default | App DB. |
| `redis` | `redis:7-alpine` | — (internal) | `core` | default | Celery broker + result backend. |
| `zap` | `zaproxy/zap-stable` | `8090` (API), `8080` (proxy) | `scan`, `targets` | default | ZAP daemon mode, controlled via API. |
| `juice-shop` | `bkimminich/juice-shop` | `3000` (only on `targets` net) | `targets` | `lab` | The first target. Behind the `lab` profile so prod-style runs don't bring it up. |
| `mailpit` | `axllent/mailpit` | `1025` (SMTP), `8025` (UI) | `core` | `dev` | Catches outbound SMTP. |
| `glitchtip` | `glitchtip/glitchtip` | `8001` | `core` | `obs` | Optional Sentry-compatible error tracker. |

Postgres and Redis are not published to the host by default — they are reachable only inside the Docker networks (CLAUDE.md §17 and the Week-1 hardening note). To inspect locally, use `docker compose exec postgres psql …` / `docker compose exec redis redis-cli …`, or add a host port mapping in `docker-compose.override.yml`. The integration-test suite (`tests/integration/`) ships an overlay that publishes Postgres on `:55432` for the duration of the test run.

Profiles let Hugo decide what's running:

- `docker compose --profile lab --profile dev up` → full local dev with target lab + mail UI.
- `docker compose up` → just the Zynksec stack, no targets.
- `docker compose --profile obs up` → adds GlitchTip when debugging hard issues.

## 0.8 Environment variables

Single source: `.env.example` at the repo root. Every variable lives here with a placeholder value. **Real secrets never go in this file.** Tracked categories:

```
# ---------- Core ----------
ZYNKSEC_ENV=dev
ZYNKSEC_LOG_LEVEL=INFO
ZYNKSEC_API_HOST=0.0.0.0
ZYNKSEC_API_PORT=8000

# ---------- PostgreSQL ----------
POSTGRES_USER=zynksec
POSTGRES_PASSWORD=changeme-local-only
POSTGRES_DB=zynksec
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
DATABASE_URL=postgresql+psycopg://zynksec:changeme-local-only@postgres:5432/zynksec

# ---------- Redis / Celery ----------
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# ---------- ZAP ----------
ZAP_API_URL=http://zap:8090
ZAP_API_KEY=changeme-local-only
ZAP_DEFAULT_PROFILE=baseline

# ---------- Mailpit (dev only) ----------
SMTP_HOST=mailpit
SMTP_PORT=1025
SMTP_FROM=zynksec@localhost

# ---------- GlitchTip (optional) ----------
GLITCHTIP_DSN=

# ---------- App ----------
APP_SECRET_KEY=please-generate-a-32-byte-base64-value
```

`pydantic-settings` reads these into a typed `Config` object in `apps/api/src/zynksec_api/config.py`. The same settings module is consumed by `apps/worker/`. This keeps drift impossible.

## 0.9 The walking-skeleton flow

The end-to-end path, step by step, that the Definition of Done in §0.2 exercises:

```
1.  Client     →  POST /scans { "target_url": "http://juice-shop:3000" }
2.  api        →  Validate request (schemas.ScanCreate)
3.  api        →  INSERT INTO scans (status='queued', target_url=…)
4.  api        →  celery.send_task("scan.run", scan_id=…)
5.  api        →  201 Created { "id": "<uuid>" }
6.  worker     →  Picks up scan.run from Redis
7.  worker     →  UPDATE scans SET status='running', started_at=now()
8.  worker     →  ZapPlugin.prepare(scan)   # builds context, validates target reachability
9.  worker     →  ZapPlugin.run(context)    # calls ZAP API: ascan + pscan baseline
10. zap        →  Crawls + tests juice-shop on the targets network
11. worker     →  Polls ZAP for completion, fetches JSON report
12. worker     →  ZapPlugin.normalize(raw)  # produces list[Finding]
13. worker     →  For each Finding: compute fingerprint, INSERT INTO findings
14. worker     →  ZapPlugin.teardown(context)
15. worker     →  UPDATE scans SET status='completed', completed_at=now()
16. Client     →  GET /scans/<uuid>
17. api        →  SELECT scan + findings, return as JSON
```

Steps 8–14 implement the ScannerPlugin contract from `03_architecture.md` for the first time. The contract is intentionally tiny in Phase 0 (one engine, one profile, one target) because every method becomes a place where Phase 1 has to handle errors, retries, partial results, and concurrency. Easier to design those once we've seen the happy path actually work end-to-end.

## 0.10 Scanner plugin contract — Phase 0 surface

The abstract base in `packages/scanners/src/zynksec_scanners/base.py` declares the minimum methods. Phase 0 only implements them for ZAP; Phase 1+ adds Nuclei, Subfinder, etc., to the same interface.

Methods (signatures only — implementations come during Phase 0 build):

- `supports(target: ScanTarget) -> bool` — does this engine know how to scan this kind of target?
- `prepare(scan: Scan) -> ScanContext` — set up engine state, validate reachability, allocate resources.
- `run(context: ScanContext) -> RawScanResult` — execute the scan; blocking, returns when done.
- `normalize(raw: RawScanResult) -> Iterator[Finding]` — turn engine-native output into the canonical `Finding` shape.
- `teardown(context: ScanContext) -> None` — release resources, clear sessions.
- `health_check() -> HealthStatus` — is this engine reachable and responsive right now?

Phase 0 will not yet implement `cancel()`, `resume()`, or `pause()` — those land in Phase 1 once we know what ZAP allows mid-scan. Documented as TODOs in the base class.

## 0.11 Finding schema — Phase 0 subset

The full Finding v1 schema in `03_architecture.md` has fifteen-ish nested fields. Phase 0 implements the subset that the walking skeleton actually populates:

```
Finding (Phase 0):
  id:               uuid
  fingerprint:      str (sha256 hex)
  schema_version:   1
  scan_id:          uuid (FK)
  target_id:        uuid (FK)

  taxonomy:
    zynksec_id:     str (e.g. "ZYN-DAST-XSS-001")
    cwe:            int | null
    owasp_top10:    str | null   (e.g. "A03:2021")

  severity:
    level:          enum(info, low, medium, high, critical)
    confidence:     enum(low, medium, high)

  location:
    url:            str
    method:         str
    parameter:      str | null

  evidence:
    engine:         "zap"
    rule_id:        str          (ZAP plugin id)
    request:        str          (raw HTTP)
    response_excerpt: str        (truncated to 4 KB)

  lifecycle:
    status:         enum(open, fixed, ignored)
    first_seen_at:  timestamp
    last_seen_at:   timestamp
```

Deferred to Phase 1: `exploitability` (KEV/EPSS), `remediation` (template_id + difficulty), `severity.score` and `severity.cvss_vector` (CVSS computation), `severity.adjustments` (context-aware bumps), `taxonomy.owasp_api_top10`, `taxonomy.category` taxonomy beyond Top 10. Schema versioning (`schema_version: 1`) is stamped from day one so Phase 1 can evolve safely.

The fingerprint formula is fixed now and **must not change** without bumping `schema_version`:

```
fingerprint = sha256(
  project_id || ":" ||
  taxonomy.zynksec_id || ":" ||
  url_normalized(location.url) || ":" ||
  location.method || ":" ||
  (location.parameter or "") || ":" ||
  payload_family(evidence.rule_id)
)
```

`payload_family` is a coarse bucket (e.g., reflected-xss, stored-xss, sqli-error-based) so cosmetically different payloads of the same class don't create duplicate findings. The mapping table lives in `packages/scanners/src/zynksec_scanners/zap/payload_families.py`.

## 0.12 Pre-commit hooks

`.pre-commit-config.yaml` runs locally on every commit and in CI as a separate job. Hooks:

- `gitleaks` — secret detection. **Push protection is also on at the GitHub side** — pre-commit catches the issue before it hits the network.
- `ruff` — Python lint + import sorting + a chunk of bug catches.
- `black` — Python format.
- `mypy` (strict) on `packages/shared-schema` only — the schema must be airtight, app code can be lenient until Phase 1.
- `prettier` — JS/TS/JSON/YAML/Markdown format.
- `eslint` — Next.js linting.
- `check-added-large-files` (max 1 MB) — keeps accidental binaries out.
- `end-of-file-fixer`, `trailing-whitespace`, `mixed-line-ending`.
- `check-merge-conflict` — catches unresolved markers.
- `check-yaml`, `check-json`, `check-toml` — syntax sanity.

Bootstrap is one line: `pre-commit install`. Documented in `README.md` Quick start.

## 0.13 GitHub Actions CI — `.github/workflows/ci.yml`

Triggers: every PR, every push to `main`. Jobs run in parallel where possible.

| Job | Tools | Failure means |
| --- | --- | --- |
| `lint-python` | ruff, black --check | Code style or lint regression. |
| `lint-js` | prettier --check, eslint | Frontend style or lint regression. |
| `typecheck-schema` | mypy --strict on `packages/shared-schema` | The Finding schema lost its types — this is non-negotiable. |
| `secrets` | Gitleaks scan of full diff + history | A credential pattern was committed. |
| `deps` | Trivy fs scan of repo | A known-vuln dep is in `pyproject.toml`/`package.json`/Dockerfiles. |
| `build-images` | docker buildx build (no push) | Dockerfiles broke. |
| `tests` | pytest (placeholder, runs zero tests in Phase 0) | Test infra broke. Real tests come Phase 1. |

What's **not** in CI yet: deployment, integration tests against a live ZAP, Semgrep rules (Phase 3), CodeQL (auto-enabled by GitHub default setup but it can't analyze code that doesn't exist).

CI runs on the `ubuntu-latest` runner. No self-hosted runners — too much ops for a solo build.

## 0.14 Observability skeleton

Phase 0 puts the pipes in even if there's nothing flowing through them yet. This is the cheapest moment to wire it.

- **Structured logging:** `structlog` configured in both `apps/api` and `apps/worker`. JSON output. One config file shared via `packages/shared-schema/src/zynksec_schema/logging.py` — yes, logging config in the schema package, because every app should agree on log shape.
- **Request ID middleware:** API generates a `X-Request-ID` header per request, propagated into the Celery task headers, propagated into structured log context.
- **Correlation ID:** every scan has a `correlation_id` (= scan UUID). Worker logs include it. Scanner plugins receive it and include it in any external API calls they make.
- **GlitchTip:** SDK installed in api + worker, DSN read from env. If the DSN is empty (default), the SDK is a no-op. Run GlitchTip locally only when debugging hard problems.
- **`/health` and `/ready`:** API exposes both. `/health` is liveness (am I a process?), `/ready` is readiness (can I talk to Postgres + Redis?). Used by Compose `depends_on: condition: service_healthy` later.
- **No `/metrics` yet.** Prometheus comes Phase 5. Adding it now would mean writing exporters that nothing scrapes.

## 0.15 Email handling in Phase 0

Mailpit catches anything the app would send. Phase 0 sends nothing — there's no auth, no notifications, no ownership-verification reminders yet. The Mailpit service is in Compose so that the *first* feature that needs email (which is ownership verification, in Phase 2) finds the SMTP infrastructure already there.

`SMTP_*` env vars resolve to Mailpit in dev; the same vars will point at Resend's SMTP relay in production. No code change needed at that boundary.

## 0.16 Seed data (`scripts/seed.py`)

Run after `docker compose up` to populate the dev DB with:

- One implicit dev `User` (id, email = `dev@zynksec.local`). Auth is bypassed in Phase 0 — every request is treated as this user.
- One `Project` (`name = "Local Dev"`).
- One `Target` (`url = http://juice-shop:3000`, `kind = web_app`, `verified_at = now`). The verification field exists from day one but is auto-set in Phase 0 because there's nothing to verify locally.
- Zero seeded `Finding` records. Findings should arrive from real scans, not fixtures, even in dev — this catches schema drift early.

Seeding is idempotent: re-running it doesn't duplicate rows.

## 0.17 The target lab (Phase 0 subset)

`target-lab/compose-targets.yml` defines vulnerable targets behind the `lab` Compose profile. Phase 0 ships only:

- **OWASP Juice Shop** (`bkimminich/juice-shop`) — the canonical "modern web app full of bugs" target. Has SQLi, XSS, broken access control, JWT issues, SSRF, and ~80 other documented challenges. Perfect breadth for testing whether ZAP's baseline scan finds *anything* useful on a modern stack.

Phase 1 adds **DVWA** (classic vuln set) and **WebGoat** (lesson-style vulns). Phase 3 adds an internal **"Zynksec Benchmark Suite"** — small intentionally-vulnerable apps that exercise specific rule packs we ship.

`target-lab/README.md` documents what's in each target and the well-known credentials. It also carries a banner: **these images contain real vulnerabilities; do not expose them on a network you don't fully control**.

## 0.18 Time budget

Hugo is solo and has no deadline. This is a pacing guide, not a commitment. Calendar weeks at "evenings + weekends" cadence:

| Week | Focus | Exit signal |
| --- | --- | --- |
| 1 | Monorepo scaffolding: pnpm workspace, Python workspaces via uv or rye, root tooling (.editorconfig, pre-commit, prettier, eslint, ruff, black, mypy configs). Compose with just postgres + redis + mailpit. FastAPI hello-world at `/health`. | `docker compose up` brings up the three services; `curl localhost:8000/health` returns 200. |
| 2 | DB layer: SQLAlchemy models for `Project`, `Scan`, `Finding` (in `packages/db`, not `apps/api`). First Alembic migration ("baseline"). Pydantic schemas. Celery worker with no-op `scan.run` task. Routes: `POST /scans` (202 + queue task), `GET /scans/{id}`. Integration test. + Next.js 15 / React 19 doc bump + ORM moved to packages/db. | A POST creates a queued scan row; the worker transitions it to completed; GET reflects the transition. |
| 3 | Worker + ZAP: Celery worker, Compose entry for ZAP daemon, `scanners` package with abstract `ScannerPlugin`, `ZapPlugin` calling ZAP's REST API for a baseline scan, normalization to `Finding`. End-to-end against juice-shop. | A POST eventually returns findings via GET. |
| 4 | Hardening + ergonomics: pre-commit hooks all green, GitHub Actions CI all green, observability (structlog, request IDs, correlation IDs), README quick-start that a stranger can follow, screenshots in `docs/`. Issue and PR templates. | A clean clone → quick-start works for someone who's never seen the repo. |

Cumulative: ~4 calendar weeks. Compresses if Hugo can put solid days in; expands without harm.

## 0.19 Risks specific to Phase 0

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| ZAP API quirks (auth header naming, async-result polling, JSON shape changes between ZAP versions) | High | Pin ZAP to a specific Stable tag in `docker-compose.yml`. Wrap every ZAP call in `ZapClient` with one place to fix things. |
| Compose network rules don't actually isolate as intended (Docker default behavior + bridge quirks) | Medium | Explicit `internal: true` on `targets` network. Verify isolation with `docker exec api curl http://juice-shop:3000` returning a network error. Document the verification command in `infra/compose/README.md`. |
| Celery task serialization issues (passing rich objects instead of IDs) | Medium | Hard rule: tasks accept primitive args only (UUIDs as strings, ints, dicts of those). Workers re-fetch from DB. Add a Ruff rule + a code-review checklist item. |
| Schema churn — Finding shape changes mid-Phase-0 and breaks downstream code | Medium | Schema lives in `packages/shared-schema` from day one. `schema_version: 1` stamped on every Finding. Any change in Phase 0 still bumps it (1.1, 1.2) — practice the discipline before it matters. |
| pre-commit too slow → Hugo bypasses it with `--no-verify` and bad commits land | Low/Medium | Keep hooks fast (skip mypy in pre-commit, run it only in CI). Document `--no-verify` as "for emergencies only" in `CONTRIBUTING.md`. |
| Solo-build energy fade because Phase 0 is invisible from the outside | Real | Tag a `v0.0.1-pre-alpha` release at the end of Phase 0 with a screenshot of a ZAP scan finding something on Juice Shop. Visible artifact, even if no one uses it yet. |

## 0.20 Phase 0 → Phase 1 handoff

Before Phase 1 design begins, Phase 0 must deliver:

1. All §0.2 exit criteria met.
2. `04_phase0_scaffolding.md` updated with anything that drifted (changed library versions, renamed services, simplified flows). This is a **post-implementation revision** — the doc captures actual reality, not the original plan.
3. A `docs/decisions/` folder created. Any non-trivial decision made *during* Phase 0 build (ORM choice details, Celery configuration tradeoffs, Compose oddities) gets a short ADR — see `engineering:architecture` skill format. Two or three ADRs is plenty.
4. The `v0.0.1-pre-alpha` tag pushed, with a release note titled "Walking skeleton" and a screenshot or asciinema cast.

Phase 1 then writes `05_phase1_dast_mvp.md` covering: auth, ownership verification, multi-scanner orchestration (adding Nuclei), the real Finding schema (full v1), basic UI for scan results, and the first proper test suite.

## Appendix A — File creation checklist

A flat list of every file Phase 0 introduces, in roughly the order they get created. Useful as a literal checklist.

```
[ ] .editorconfig
[ ] .nvmrc
[ ] pnpm-workspace.yaml
[ ] package.json (root)
[ ] pyproject.toml (root)
[ ] .pre-commit-config.yaml
[ ] .env.example
[ ] docker-compose.yml
[ ] docker-compose.override.example.yml
[ ] infra/docker/api.Dockerfile
[ ] infra/docker/worker.Dockerfile
[ ] infra/docker/web.Dockerfile
[ ] infra/compose/postgres-init.sql
[ ] infra/compose/zap-config/ (if ZAP needs config files)
[ ] target-lab/README.md
[ ] target-lab/compose-targets.yml
[ ] packages/shared-schema/pyproject.toml
[ ] packages/shared-schema/src/zynksec_schema/__init__.py
[ ] packages/shared-schema/src/zynksec_schema/finding.py
[ ] packages/shared-schema/src/zynksec_schema/logging.py
[ ] packages/scanners/pyproject.toml
[ ] packages/scanners/src/zynksec_scanners/__init__.py
[ ] packages/scanners/src/zynksec_scanners/base.py
[ ] packages/scanners/src/zynksec_scanners/zap/__init__.py
[ ] packages/scanners/src/zynksec_scanners/zap/plugin.py
[ ] packages/scanners/src/zynksec_scanners/zap/payload_families.py
[ ] apps/api/pyproject.toml
[ ] apps/api/alembic.ini
[ ] apps/api/alembic/env.py
[ ] apps/api/alembic/versions/0001_baseline.py
[ ] apps/api/src/zynksec_api/__init__.py
[ ] apps/api/src/zynksec_api/main.py
[ ] apps/api/src/zynksec_api/config.py
[ ] apps/api/src/zynksec_api/db.py
[ ] apps/api/src/zynksec_api/models/{user,project,target,scan,finding}.py
[ ] apps/api/src/zynksec_api/schemas/{scan,finding,health}.py
[ ] apps/api/src/zynksec_api/routers/{health,projects,scans}.py
[ ] apps/worker/pyproject.toml
[ ] apps/worker/src/zynksec_worker/__init__.py
[ ] apps/worker/src/zynksec_worker/celery_app.py
[ ] apps/worker/src/zynksec_worker/tasks/scan.py
[ ] apps/worker/src/zynksec_worker/runners/zap_runner.py
[ ] apps/web/package.json
[ ] apps/web/next.config.mjs
[ ] apps/web/tailwind.config.ts
[ ] apps/web/app/page.tsx
[ ] apps/web/app/api/health/route.ts
[ ] scripts/bootstrap.sh
[ ] scripts/seed.py
[ ] scripts/scan-juice-shop.sh
[ ] .github/workflows/ci.yml
[ ] .github/ISSUE_TEMPLATE/bug_report.yml
[ ] .github/ISSUE_TEMPLATE/design_review.yml
[ ] .github/ISSUE_TEMPLATE/config.yml
[ ] .github/pull_request_template.md
[ ] README.md (Quick start section, post-build)
```

That's Phase 0. Once this is real, Zynksec exists.
