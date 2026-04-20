# Zynksec — Technical Architecture

**Owner:** Hugo Herrera
**Status:** Draft v0.1
**Date:** 2026-04-19
**Companion to:** `01_scoping_and_roadmap.md` (v0.2), `02_product_strength_and_foundations.md`

---

## 0. Decisions locked (from previous docs)

- **License:** AGPLv3 for the core, with proprietary rule packs and SaaS add-ons later.
- **First framework profile:** Next.js + Vercel.
- **Scan intensity defaults:** Passive + Standard in Phase 1, Deep added in Phase 2.
- **AI/LLM coverage:** Phase 4 (no budget pressure; keep scope tight).
- **Core stack:** Python 3.12 + FastAPI + Celery + Redis + PostgreSQL + Next.js. All scanners run as Docker containers. Everything free and self-hostable.

This document is the technical blueprint. It defines the components, their contracts, and how they communicate — enough detail that implementation becomes mechanical, but no code is written yet.

---

## 1. Architectural goals

The architecture is optimized for four things, in priority order:

1. **Trustworthiness of findings.** The system must never invent findings. Every finding must be traceable to an engine, a rule, and reproducible evidence.
2. **Safety of scans.** The system must not scan unauthorized targets, must not be abused as a weapon, and must not accidentally break production.
3. **Solo-maintainability.** One person must be able to own every layer. No microservice sprawl, no exotic tech, no ops nightmares.
4. **Frictionless scaling later.** Today's code must run on a €5 VPS; tomorrow's code must run on Kubernetes without a rewrite.

Everything else — performance, features, UI polish — sits below these four.

---

## 2. System overview

Zynksec is a **monolithic FastAPI application plus stateless Celery workers**, with scanners running as containerized subprocesses invoked by those workers. Communication between components is either HTTP (user-facing), Celery task dispatch (API → workers), or subprocess invocation (worker → scanner container).

### 2.1 Component map

```
┌──────────────────────────────────────────────────────────────────┐
│                          User's Browser                           │
└───────────────┬──────────────────────────────────────────────────┘
                │ HTTPS
                ▼
┌───────────────────────────┐          ┌───────────────────────────┐
│   Next.js frontend        │          │   Vercel/GitHub webhooks  │
│   (auth, dashboard, UI)   │          │   (deploy-triggered scan) │
└───────────────┬───────────┘          └──────────────┬────────────┘
                │ REST/JSON                           │
                ▼                                     ▼
┌──────────────────────────────────────────────────────────────────┐
│                       FastAPI API service                         │
│  Auth • Projects • Targets • Scans • Findings • Webhooks • Audit │
└────┬────────────┬─────────────────────────┬──────────────────────┘
     │            │                         │
     │ SQL        │ enqueue                 │ sign/verify
     ▼            ▼                         ▼
┌─────────┐  ┌──────────┐             ┌─────────────┐
│Postgres │  │  Redis   │◄───────────►│Object Store │
│(source  │  │(queue +  │             │(evidence    │
│of truth)│  │ cache +  │             │ blobs,      │
│         │  │ ratelim) │             │ reports)    │
└─────────┘  └─────┬────┘             └─────────────┘
                   │
                   │ Celery task dispatch
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Orchestrator worker pool                       │
│   Takes scan jobs, plans the pipeline, fans out to scanners      │
└──┬───────────────────────────────────────────────────────────────┘
   │ subprocess / HTTP
   ▼
┌──────────────────────────────────────────────────────────────────┐
│               Scanner worker pool (isolated network)              │
│   ZAP • Nuclei • httpx • Subfinder • Katana • Naabu • testssl    │
│   Later: Semgrep • Gitleaks • Trivy • Syft • Grype               │
└──┬───────────────────────────────────────────────────────────────┘
   │ raw findings
   ▼
┌──────────────────────────────────────────────────────────────────┐
│              Post-processing pipeline (orchestrator)              │
│   Normalizer → Correlator → Prioritizer → Template binder        │
└──┬───────────────────────────────────────────────────────────────┘
   │ persisted findings
   ▼
           (back to Postgres & object store)


┌──────────────────────────────┐     ┌──────────────────────────────┐
│   Interactsh OOB server      │     │   Target lab (dev only)      │
│   (self-hosted, dedicated    │     │   Juice Shop, DVWA, crAPI,   │
│    subdomain, Phase 2+)      │     │   VAmPI on isolated network  │
└──────────────────────────────┘     └──────────────────────────────┘
```

### 2.2 Why a monolith (and why it scales anyway)

The API is a single FastAPI service, not a collection of microservices. This is deliberate and important for a solo build:

- One codebase, one deploy, one set of migrations.
- Modules inside the monolith enforce boundaries via Python package structure, not network boundaries.
- When a module proves it needs to scale independently (e.g., webhooks under load), it can be extracted with minimal refactoring because its dependencies are already explicit.

Celery workers are separate processes and are the only part of the system that scales horizontally in Phase 1. Since every unit of work (a scan, a scanner run, a post-processing task) is a queued task, horizontal scaling is "run more workers" — no code change required.

---

## 3. Deployment topology

### 3.1 Local development (Phase 0 → Phase 5)

Docker Compose file defines the full stack:

- `api` — FastAPI container
- `worker` — Celery worker container (can be run N times)
- `scheduler` — Celery beat (for scheduled rescans)
- `frontend` — Next.js dev container
- `postgres` — PostgreSQL 16
- `redis` — Redis 7
- `minio` — S3-compatible object store (so prod behavior matches dev)
- `interactsh` — self-hosted OOB server (Phase 2+)
- `prometheus` + `grafana` + `loki` — observability (can be started lazily)

A second Docker Compose file (`docker-compose.targets.yml`) defines the isolated target lab: Juice Shop, DVWA, crAPI, VAmPI, on a separate Docker network that Zynksec workers can reach but nothing else can.

### 3.2 Single VPS (Phase 4 → Phase 6)

Same Docker Compose file deployed to one VPS (target: Hetzner CAX11 ARM, ~€3.85/mo). Caddy as the reverse proxy with automatic TLS from Let's Encrypt. Backups via `pg_dump` to an external free S3-compatible store (e.g., Backblaze B2 free tier or Cloudflare R2 free tier).

### 3.3 Kubernetes (Phase 7+, commercial viability stage)

Same containers, different orchestration. The key properties that make this "free" as a future migration:

- Workers are already stateless.
- Secrets already come from environment variables (dev) or SOPS-sealed files (prod), not baked into images.
- Scanner isolation is expressed via Docker networks today; the exact same intent maps to Kubernetes NetworkPolicies.
- Database and Redis get managed-service-or-self-hosted variants — both work.

No work is required in Phase 1 to prepare for Kubernetes beyond keeping the app stateless.

### 3.4 Network zones (enforced from Phase 0)

Three logical network zones, expressed as Docker networks in dev, as Kubernetes namespaces + NetworkPolicies in prod:

| Zone | Contents | Can reach |
|---|---|---|
| `zynksec-core` | API, Postgres, Redis, MinIO, frontend | Only within zone + internet for LetsEncrypt/auth callbacks |
| `zynksec-scan` | Scanner worker pods, orchestrator | Verified target domains, Interactsh, nowhere else |
| `zynksec-targets` | DVWA, Juice Shop, etc. (dev only) | Nothing (isolated) |

Enforcement: in Docker Compose, no shared network between `core` and `scan` except for a single internal bridge used by Celery to push tasks in and results out. Egress from `scan` gated by a local HTTP proxy (Caddy with domain allowlist) — every scanner subprocess is configured to use the proxy for HTTPS; any traffic to a non-allowlisted domain is blocked.

---

## 4. Domain model

The ten core entities and their relationships. Zynksec's mental model lives here.

```
Organization ──1:N── User
     │
     └──1:N── Project ──1:N── Target ──1:N── OwnershipVerification
                                 │
                                 └──1:N── Scan ──1:N── ScannerRun ──1:N── RawFinding
                                            │                                 │
                                            └─────────────(post-processing)───┘
                                                          │
                                                          ▼
                                                       Finding ──1:N── FindingEvidence
                                                          │
                                                          └──N:1── RemediationTemplate
```

### 4.1 Entity descriptions

- **Organization**: the tenant boundary. Every user belongs to one or more organizations; every project belongs to exactly one. For MVP a user has a personal organization and can create more later.
- **User**: authenticated principal. Linked to GitHub for OAuth.
- **Project**: a logical grouping ("my SaaS product"). Contains targets and, later, repositories.
- **Target**: something we scan — a URL, an API base URL, a subdomain set. Has at least one ownership verification before active scans are allowed.
- **OwnershipVerification**: a record that a target was proven owned at a point in time. Method (DNS / well-known-file), token, verified_at, expires_at.
- **Scan**: a single scan invocation. Carries the profile, intensity, status, and ownership of its results.
- **ScannerRun**: one scanner's execution within a scan. ZAP and Nuclei each produce a ScannerRun. Has its own lifecycle state.
- **RawFinding**: what a scanner produced natively. Preserved for debuggability and provenance. Never shown directly to users.
- **Finding**: the normalized, deduplicated, user-facing finding. Has a stable fingerprint that persists across scans of the same target.
- **FindingEvidence**: attached to a finding, one per corroborating engine. Contains request/response/proof.
- **RemediationTemplate**: static markdown content keyed by taxonomy ID, shown to users. Community-extendable in Phase 5.
- **AuditLogEntry**: every user-visible action, with actor/target/timestamp.

### 4.2 Database schema (Postgres, nominal)

Only the load-bearing tables shown. Standard audit columns (`created_at`, `updated_at`, `deleted_at`) are implied everywhere.

```
organizations(id, name, slug, plan_tier, created_by_user_id)

users(id, email, github_id, name, avatar_url, last_login_at)

memberships(user_id, organization_id, role)  -- role: owner|admin|member|viewer

projects(id, organization_id, name, slug, description)

targets(
  id, project_id,
  kind,              -- "web" | "api" | "repo" (repo in Phase 3)
  display_name,
  base_url,          -- for web/api targets
  openapi_spec_ref,  -- optional blob pointer
  repo_url,          -- for Phase 3
  created_by_user_id
)

ownership_verifications(
  id, target_id,
  method,            -- "dns_txt" | "well_known"
  token,
  status,            -- "pending" | "verified" | "failed" | "expired"
  verified_at,
  expires_at,
  last_checked_at
)

framework_profiles(
  id, target_id,
  detected_at,
  stack,             -- JSONB: { "framework": "next.js", "version": "14", "host": "vercel", "auth": "clerk", ... }
  confidence,
  profile_key        -- "nextjs_vercel" | "laravel" | "generic_web" | ...
)

scans(
  id, target_id, initiated_by_user_id,
  intensity,         -- "passive" | "standard" | "deep"
  status,            -- see state machine §7
  profile_key_snapshot,  -- frozen at scan start, so changes to framework_profiles don't break history
  started_at, completed_at,
  trigger,           -- "manual" | "scheduled" | "webhook" | "verification"
  summary_stats      -- JSONB: counts by severity, duration, coverage summary
)

scanner_runs(
  id, scan_id,
  scanner_id,        -- "zap" | "nuclei" | "testssl" | ...
  scanner_version,
  status,            -- "queued" | "running" | "succeeded" | "failed" | "skipped"
  started_at, completed_at,
  stderr_ref,        -- blob pointer (optional)
  exit_code
)

raw_findings(
  id, scanner_run_id,
  engine_native_id,  -- scanner's own ID for this finding
  raw_payload        -- JSONB, whatever the scanner emitted
)

findings(
  id,
  project_id,        -- denormalized for query speed
  target_id,
  fingerprint,       -- unique per (project_id, fingerprint)
  taxonomy_zynksec_id,
  taxonomy_cwe,
  taxonomy_owasp_top10,
  taxonomy_owasp_api_top10,
  title,
  description,
  severity_level,
  severity_score,
  severity_cvss_vector,
  severity_confidence,
  exploitability,    -- JSONB: { kev_match, epss_score, auth_required, ... }
  location,          -- JSONB: { url, method, parameter, file, line, ... }
  remediation_template_id,
  lifecycle_status,  -- see lifecycle §11
  first_seen_at, last_seen_at, last_verified_at,
  first_scan_id, last_scan_id
)

finding_evidence(
  id, finding_id, scanner_run_id,
  engine,
  rule_id,
  captured_at,
  request,           -- JSONB (sanitized)
  response,          -- JSONB (body possibly truncated)
  response_body_ref, -- blob pointer for full body
  proof              -- JSONB: { type: "diff"|"oob"|"timing"|..., details }
)

finding_status_history(
  id, finding_id,
  timestamp, event, actor_user_id, notes
)

remediation_templates(
  id, zynksec_id,    -- maps to taxonomy_zynksec_id
  version, content_md,
  difficulty, estimated_effort
)

audit_log(
  id, organization_id, user_id,
  timestamp, action, target_type, target_id, metadata
)

api_keys(
  id, user_id, name,
  key_hash, last_used_at, expires_at
)
```

Indexes that matter from day one:
- `findings(project_id, fingerprint)` — unique, used for dedupe.
- `findings(project_id, lifecycle_status, severity_level)` — drives the dashboard list.
- `scanner_runs(scan_id)` — used constantly during scan processing.
- `finding_evidence(finding_id)`.
- `audit_log(organization_id, timestamp desc)`.

### 4.3 Object storage layout

MinIO locally, any S3-compatible store in production. One bucket per environment.

```
zynksec-{env}/
  evidence/
    {finding_id}/
      {evidence_id}/request.txt
      {evidence_id}/response.bin
      {evidence_id}/proof.json
  raw-scanner-output/
    {scanner_run_id}/
      zap-report.json
      nuclei-findings.jsonl
      stderr.log
  reports/
    {scan_id}/snapshot.pdf
  sbom/               # Phase 3+
    {scan_id}/sbom.cdx.json
```

Lifecycle rules: raw scanner output kept 90 days, evidence 30 days (per the privacy policy), SBOMs kept indefinitely, reports indefinitely.

---

## 5. The Finding schema (canonical wire format, v1)

This is the single most important contract in the system. Every internal module and external export (JSON, SARIF, PDF) serializes from this shape.

```yaml
Finding:
  # Identity
  id: uuid
  fingerprint: string                # deterministic hash, see §5.1
  schema_version: 1

  # Classification
  taxonomy:
    zynksec_id: string               # e.g., "ZS-AUTH-JWT-NONE-001"
    cwe: string | null               # e.g., "CWE-287"
    owasp_top10: string | null       # e.g., "A07:2021"
    owasp_api_top10: string | null   # e.g., "API2:2023"
    category: enum                   # "auth" | "access_control" | "injection" | ...

  # Display
  title: string                      # short human-readable
  description: string                # one-paragraph plain-language
  severity:
    level: enum                      # "critical" | "high" | "medium" | "low" | "info"
    score: float                     # 0.0 - 10.0
    cvss_vector: string | null       # CVSS v4 vector
    confidence: enum                 # "low" | "medium" | "high"
    adjustments: array               # list of applied modifiers (KEV, EPSS, auth_required, etc.)

  # Exploitability context
  exploitability:
    kev_match: bool
    epss_score: float | null         # 0.0 - 1.0
    auth_required: bool
    requires_user_interaction: bool
    network_accessible: bool

  # Where the issue is
  location:
    target_id: uuid
    url: string | null
    method: string | null
    parameter: string | null
    repository: string | null        # Phase 3+
    file_path: string | null
    line_number: int | null

  # What proves it
  evidence:
    - engine: string                 # "zap" | "nuclei" | "testssl" | "interactsh" | ...
      engine_version: string
      rule_id: string                # engine-specific rule identifier
      captured_at: timestamp
      request:
        method: string
        url: string
        headers: map<string, string>
        body_sha256: string
        body_ref: string | null      # pointer to object store
      response:
        status: int
        headers: map<string, string>
        body_excerpt: string
        body_ref: string | null
      proof:
        type: enum                   # "diff" | "string_match" | "oob_callback" |
                                     #   "timing" | "status_code" | "introspection"
        details: object              # shape depends on type
        narrative: string            # human-readable one-liner of what was proven

  # What to do about it
  remediation:
    template_id: string
    difficulty: enum                 # "easy" | "medium" | "hard"
    estimated_effort: string         # "15 minutes" | "half day" | ...
    contextual_notes: string | null  # Phase 6+ AI-generated

  # Lifecycle
  lifecycle:
    status: enum                     # see §11
    first_seen_at: timestamp
    last_seen_at: timestamp
    last_verified_at: timestamp | null
    scan_ids: array<uuid>            # every scan that produced this finding
```

### 5.1 Fingerprinting rule (critical for dedupe)

A finding's `fingerprint` is a SHA-256 of a canonical tuple:

```
sha256(
  project_id
  + "|" + taxonomy.zynksec_id
  + "|" + location.url_normalized          # scheme+host+path, query-key-sorted
  + "|" + location.method
  + "|" + location.parameter
  + "|" + payload_family                   # e.g., "sqli-time-based" not the exact payload
)
```

Notes:
- `location.url_normalized` strips tracking query params, normalizes trailing slashes, lowercases host.
- `payload_family` is provided by the normalizer for each engine — not the raw payload.
- This lets a SQLi found by ZAP and a SQLi found by Nuclei on the same parameter become the same finding with two pieces of evidence and higher confidence.

### 5.2 Export formats derived from this schema

- **JSON** — direct serialization, pretty-printed.
- **SARIF 2.1** — for GitHub Code Scanning / IDE integrations. Mapping defined once and tested.
- **PDF snapshot** — rendered via WeasyPrint (free, Python).
- **CSV** — for spreadsheet exports.
- **Webhook payload** — same JSON shape, delivered with HMAC signature.

---

## 6. Scanner plugin contract

Every scanner integrated into Zynksec is a plugin implementing a common interface. This is how we ensure adding a new scanner is a one-day task.

### 6.1 Plugin interface (conceptual)

```
Scanner:
  # Static metadata (class-level)
  id: str                          # stable identifier: "zap", "nuclei", "testssl"
  display_name: str
  engine_version: str              # version of the underlying tool we package
  supported_target_kinds: set      # {"web", "api"} for ZAP; {"web"} for testssl; etc.
  supported_intensities: set       # {"passive", "standard", "deep"} per scanner
  required_capabilities: set       # {"oob"} for SSRF scanner, {"repo_read"} for Semgrep

  # Capability check
  supports(target, intensity, profile) -> bool
    # Decides whether this scanner runs for this combination.

  # Duration hint (used for scheduling + UX)
  estimated_duration(target, intensity, profile) -> timedelta

  # Lifecycle
  prepare(scan_context) -> PreparedRun
    # Builds the scanner config (e.g., ZAP Automation Framework YAML)
    # from target, profile, and auth credentials.
    # Returns an opaque object the orchestrator passes to run().

  run(prepared_run) -> async iterator of RawFinding
    # Invokes the scanner container, streams raw findings.
    # Must be cancellable via asyncio task cancellation.

  normalize(raw_finding) -> list of Finding
    # Maps one raw finding to zero or more Zynksec Findings.
    # Attaches Evidence with request/response/proof.

  teardown(prepared_run) -> None
    # Cleans up temporary files, container artifacts.

  health_check() -> ScannerHealth
    # Called periodically by the orchestrator; verifies the scanner
    # container can be launched and responds.
```

### 6.2 What the orchestrator guarantees to a scanner

- A pre-verified target (or passive-only intensity if not verified).
- A working directory writable by the scanner container.
- Egress via the sanctioned proxy (traffic to anywhere else is blocked).
- A clean environment — no leaked credentials from other scans.
- A cancellation signal if the scan is stopped or times out.

### 6.3 What the scanner promises the orchestrator

- Emits structured raw findings with stable native IDs.
- Respects the provided rate-limit config.
- Exits cleanly on cancellation within a grace period.
- Never writes outside its working directory.
- Returns a non-zero exit code on fatal failures so the orchestrator can mark the ScannerRun failed.

### 6.4 Scanner roster (Phase-by-Phase)

| Scanner | Phase | Purpose | Invocation |
|---|---|---|---|
| ZAP | 1 | DAST core (passive + active) | Docker + HTTP API |
| testssl.sh | 1 | TLS analysis | Docker subprocess |
| Nuclei | 1 | Template-based DAST | Docker subprocess |
| Subfinder | 2 | Subdomain discovery | Docker subprocess |
| httpx | 2 | Live host fingerprinting | Docker subprocess |
| Katana | 2 | Deep crawling | Docker subprocess |
| Naabu | 2 | Port discovery | Docker subprocess |
| Interactsh client | 2 | OOB correlation | Internal HTTP client |
| Semgrep | 3 | SAST | Docker subprocess |
| Gitleaks | 3 | Secrets | Docker subprocess |
| Trivy | 3 | SCA + image + IaC | Docker subprocess |
| OSV-Scanner | 3 | Dep CVE | Docker subprocess |
| Syft + Grype | 3 | SBOM + CVE correlation | Docker subprocess |
| Garak (wrapped) | 4 | LLM vuln probes | Docker subprocess |

---

## 7. Scan orchestration — the state machine

Every scan moves through a strict state machine. The orchestrator is the only component that transitions states; all other components read them.

### 7.1 States

| State | Meaning |
|---|---|
| `CREATED` | Scan record created, not yet dispatched. |
| `QUEUED` | Dispatched to Celery, awaiting a worker. |
| `PREPARING` | Worker picked up; fingerprinting target and selecting profile. |
| `AWAITING_VERIFICATION` | Active scan requested but target not verified — waiting or downgrading. |
| `RUNNING_PASSIVE` | Running passive-intensity scanners. |
| `RUNNING_STANDARD` | Running standard-intensity scanners. |
| `RUNNING_DEEP` | Running deep-intensity scanners (Phase 2+). |
| `POST_PROCESSING` | Normalization, dedupe, correlation, prioritization. |
| `COMPLETED` | Terminal success. |
| `PARTIAL` | Terminal; some scanners failed but scan yielded findings. |
| `FAILED` | Terminal; no usable output. |
| `CANCELLED` | Terminal; user or system cancelled. |

### 7.2 Transition diagram

```
              CREATED
                 │
                 ▼
              QUEUED ─────────► CANCELLED (by user)
                 │
                 ▼
             PREPARING
                 │
          ┌──────┴──────┐
          │             │
          ▼             ▼
    AWAITING_      (profile chosen,
    VERIFICATION    verified or passive-only)
          │             │
          ▼             ▼
     (downgrade     RUNNING_PASSIVE
      to passive        │
      or wait)          ▼
                   RUNNING_STANDARD (if intensity ≥ standard)
                        │
                        ▼
                   RUNNING_DEEP    (if intensity = deep, Phase 2+)
                        │
                        ▼
                   POST_PROCESSING
                        │
           ┌────────────┼────────────┐
           ▼            ▼            ▼
       COMPLETED    PARTIAL       FAILED
```

### 7.3 Per-transition rules

- Transitioning into `RUNNING_STANDARD` or `RUNNING_DEEP` **requires** ownership verification to be active (not expired). If verification expires mid-scan, remaining active scanners are aborted and the scan finishes as `PARTIAL`.
- Transitioning into `POST_PROCESSING` is always entered, even if some scanners failed — partial findings are still valuable.
- `FAILED` is only reached if post-processing itself couldn't produce any findings or if the target was unreachable.
- Timeouts are enforced at both scanner-run level (per-scanner) and scan level (30 / 60 / 120 minutes for Passive / Standard / Deep). Timeouts force `PARTIAL` terminal.

### 7.4 Cancellation semantics

User-triggered cancellation posts a flag to Redis. The orchestrator polls the flag between scanner-run boundaries. In-flight scanners are cancelled via Celery task cancellation (scanner subprocesses receive `SIGTERM`, then `SIGKILL` after grace period).

---

## 8. Framework fingerprinting subsystem

Fingerprinting runs in the `PREPARING` state and sets `scans.profile_key_snapshot`. The output drives rule selection, auth flow templates, and custom probes.

### 8.1 Fingerprinting inputs

1. HTTP response from `GET /` (headers, body, status).
2. HTTP response from a handful of well-known paths: `/favicon.ico`, `/robots.txt`, `/_next/static/chunks/main.js`, `/api/health`.
3. Cookie names observed.
4. TLS certificate (if any).
5. DNS records (especially CNAME, for host detection).

### 8.2 Detection rules

Rules are declarative, stored in `packages/fingerprint/rules/*.yaml`, each rule:

```yaml
rule_id: "nextjs-vercel-v1"
profile_key: "nextjs_vercel"
confidence: high
matches:
  any:
    - header: "x-vercel-id"
      exists: true
    - cookie: "__vercel_live_token"
    - path: "/_next/static/chunks/main.js"
      status: 200
    - html_meta: "next-head-count"
derived:
  framework: "next.js"
  host: "vercel"
```

Rules can stack (a target may match multiple, yielding a composite profile key like `nextjs_vercel_supabase_clerk`).

### 8.3 Profile → scan plan

A **profile** is a named bundle of:

- Which scanners to run.
- Which Nuclei template packs to load.
- Which ZAP Automation Framework YAML to use.
- Which auth flow template to offer the user (Clerk / Auth.js / Supabase / custom).
- Which custom Zynksec rule packs to apply.

Profiles live in `packages/profiles/<profile_key>/`.

### 8.4 Next.js + Vercel profile (Phase 1 shipping target)

Contents:

- **Scanners enabled:** ZAP (passive + standard), Nuclei, testssl.sh.
- **Nuclei packs:** generic web + custom `zynksec-nextjs` pack.
- **ZAP plan:** `zap/plans/nextjs-vercel.yaml` — includes crawling `/_next/static/`, API route enumeration, source-map fetching.
- **Custom probes:**
  - Fetch `/_next/static/chunks/*.js` → search for secrets matching patterns like `NEXT_PUBLIC_*`, `sk_live_`, Supabase service role key format, `eyJ` JWT-looking strings, API tokens.
  - Fetch `.js.map` files when exposed; flag.
  - Probe for `/api/*` authentication gaps (unauthenticated request expecting 401/403).
  - Detect Vercel preview domain patterns; flag if discovered on the same org.
- **Auth flow templates offered:** Clerk, Auth.js, Supabase Auth, custom cookie/JWT.
- **Remediation mapping:** each Next.js-specific finding maps to a template that cites Next.js documentation directly (e.g., "Use `NEXT_PUBLIC_` prefix only for non-secret values — see Next.js env-var docs").

### 8.5 Fingerprint caching

Framework profiles are cached per target for 24 hours. Explicit re-fingerprinting is triggered on deploy webhooks or user request.

---

## 9. Ownership verification

Active scanning requires proof of ownership. Zynksec enforces this at the API layer: scans with `intensity > passive` can only be created against verified targets.

### 9.1 Verification methods

**Method A — DNS TXT record:**
1. User adds a target. Zynksec generates a random token and shows: *Add a TXT record at `_zynksec-verify.example.com` with value `zsv=<token>`.*
2. User sets the record.
3. User clicks "Verify." Zynksec queries the TXT record from multiple resolvers (Google, Cloudflare, Quad9) and confirms.
4. On success, `ownership_verifications.status = verified`, `verified_at = now()`, `expires_at = now() + 90 days`.

**Method B — well-known file:**
1. User adds a target. Zynksec generates a token.
2. User places content `zsv=<token>` at `https://example.com/.well-known/zynksec-verify.txt`.
3. Zynksec fetches from multiple egress IPs (to avoid tricks) and verifies.
4. Same persistence rule as above.

### 9.2 Re-verification

A background Celery beat task re-checks all `verified` rows daily. If the record/file disappears, status transitions to `expired` and active scans against that target are auto-disabled. The user is emailed.

### 9.3 Anti-abuse

- Max 5 pending verifications per user per day.
- Max 20 verified targets per organization on the free plan.
- IP and user-agent of verification requests are logged.
- Verification tokens expire after 72 hours if not used.

---

## 10. Authentication and authorization

### 10.1 Authentication

- **Phase 1**: GitHub OAuth only (one-click, no password). Email forwarding from GitHub's verified email.
- **Phase 2**: Optional email/password with magic-link reset.
- **Phase 5+**: SAML/OIDC for organizations.

Session management:
- Session stored server-side in Redis; cookie contains opaque session ID.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax`.
- Session lifetime 30 days; sliding; server-revocable.
- CSRF protection via double-submit-cookie for state-changing endpoints.

### 10.2 Authorization (RBAC within organizations)

Four roles within an organization:

| Role | Can |
|---|---|
| **owner** | Everything; manage billing (later); delete org |
| **admin** | Manage projects, members, settings |
| **member** | Create/run scans, triage findings |
| **viewer** | Read-only |

Role checks live in FastAPI dependencies, applied per endpoint. Authorization is **deny by default**.

### 10.3 API keys (Phase 2+)

Users can generate API keys scoped to an organization with a subset of permissions. Keys are hashed at rest. Used for CI integrations and webhooks.

---

## 11. Finding lifecycle

A Finding moves through these statuses, driven by the user and the system:

| Status | Set by | Meaning |
|---|---|---|
| `open` | system | New finding, unreviewed |
| `triaged` | user | Acknowledged, queued for fix |
| `confirmed` | user | User verified it's real and exploitable |
| `fixed` | user | User claims it's fixed; awaiting verification |
| `verified_fixed` | system | Post-fix rescan confirmed the issue is gone |
| `accepted_risk` | user | Known issue, business decision not to fix |
| `false_positive` | user | User says Zynksec is wrong |
| `obsolete` | system | Target or finding location no longer exists |

Rules:
- A finding that doesn't appear in a scan for N consecutive scans (default 3) auto-transitions to `obsolete` if its status is `open`. Triaged/confirmed findings are not auto-obsoleted.
- `fixed` → `verified_fixed` happens after a targeted rescan of the specific endpoint with the specific payload confirms absence.
- `false_positive` clicks feed the prioritizer (aggregate FP rate per rule_id).
- Status transitions are always recorded in `finding_status_history`.

---

## 12. Scan pipeline — end-to-end flow

This is how a single scan actually executes, end to end, once we're past `QUEUED`.

1. **Prepare** (orchestrator task)
   - Acquire target + ownership status.
   - Run fingerprinter → determine `profile_key`.
   - Select scanners per profile + intensity.
   - Create a `ScannerRun` record for each selected scanner, status `queued`.
2. **Dispatch scanner runs** (fan-out)
   - Each `ScannerRun` becomes its own Celery task, dispatched in parallel where scanners don't conflict.
   - Conflict rules: at most one active ZAP scan per target at a time (ZAP can saturate a target); passive scanners run freely.
3. **Execute scanner** (per scanner worker)
   - `prepare()` builds config; secrets mounted from Vault/SOPS.
   - `run()` invokes the containerized scanner, streams raw findings into `raw_findings` table.
   - On completion, `teardown()`.
   - Emits metrics/traces.
4. **Normalize** (fan-in, orchestrator)
   - For each raw finding, call scanner's `normalize()`. Produces zero or more draft Findings with Evidence.
   - Draft Findings are held in memory; not yet persisted as Findings.
5. **Correlate and dedupe** (orchestrator)
   - Compute fingerprint for each draft Finding.
   - Match against existing findings in DB with same fingerprint. If exists: append Evidence, update `last_seen_at`, increase confidence if new engine corroborates.
   - If not exists: insert new Finding.
6. **Prioritize** (orchestrator)
   - Run the scoring function (severity × exploitability × confidence × asset criticality).
   - Update `severity_score`, `adjustments` list.
7. **Bind remediation templates** (orchestrator)
   - Look up template by `taxonomy_zynksec_id`.
   - Persist reference; contextual notes remain null until Phase 6.
8. **Finalize** (orchestrator)
   - Write scan summary stats.
   - Transition scan status to `COMPLETED` or `PARTIAL`.
   - Emit `scan.completed` event for webhooks / email / audit log.

Each of steps 1–8 is its own Celery task with retry semantics; a failure in step N doesn't lose work in steps 1 through N-1 because everything persists to Postgres as it progresses.

---

## 13. Correlation + prioritization logic

### 13.1 Correlation rules

- Two raw findings with the same fingerprint collapse into one Finding with multiple Evidence items.
- Corroboration increases confidence: one engine = `low`, two engines = `medium`, three or more = `high`.
- Corroboration of a passive and an active finding on the same endpoint is weighted higher than two passive findings.

### 13.2 Prioritization inputs

The prioritizer reads:

- Base severity from the engine (normalized to critical/high/medium/low/info).
- CVSS score (if mappable).
- KEV match flag (from CISA KEV, synced daily).
- EPSS score (from FIRST.org, synced daily).
- `auth_required` flag.
- Asset criticality (user-tagged per target; default `medium`).

### 13.3 Score computation (pseudocode)

```
score = base_severity_score
if kev_match: score = max(score, 8.0)
if epss_score and epss_score > 0.5: score = max(score, 7.0)
if auth_required: score = score * 0.85
if asset_criticality == "high": score = score * 1.15
if asset_criticality == "low": score = score * 0.9
if confidence == "low": score = score * 0.85
level = bucket(score)   # 0-3.9 info/low, 4-6.9 medium, 7-8.9 high, 9+ critical
```

These weights are tunable via a config file so we can adjust without a deploy.

### 13.4 False-positive feedback effect

When users mark findings as `false_positive`:
- The specific finding is closed.
- A counter increments per `(scanner_id, rule_id)`.
- When FP rate for a rule crosses a threshold (say 40% over 20+ reports), that rule's base severity is auto-demoted by one level and a notification goes to maintainers for review.
- This is the compounding-trust mechanism.

---

## 14. Job queue architecture

### 14.1 Queues

Celery is configured with named queues so different workloads don't starve each other:

| Queue | Handles | Worker concurrency |
|---|---|---|
| `orchestration` | scan lifecycle, post-processing | moderate (CPU-light) |
| `scanners.web` | ZAP, Nuclei, testssl | low (heavy, long-running) |
| `scanners.recon` | Subfinder, httpx, Katana, Naabu | moderate |
| `scanners.repo` | Semgrep, Gitleaks, Trivy, OSV | moderate (Phase 3+) |
| `verification` | ownership re-checks | high |
| `webhooks` | incoming webhook handling | high |
| `periodic` | Celery beat jobs | low |

### 14.2 Retry and idempotency

- Every task is written to be idempotent: running it twice produces the same outcome.
- Tasks use Postgres row-level optimistic locking or Redis `SETNX` to prevent double-execution of the same scan.
- Retries use exponential backoff with jitter: 10s, 30s, 2m, 10m, 1h, dead-lettered after 5 tries.
- Dead-lettered tasks are inspectable through the admin UI.

### 14.3 Timeouts

- Per-task soft timeout (SIGTERM then grace period) and hard timeout (SIGKILL).
- Scanner tasks have scanner-specific timeouts in config: ZAP standard = 30 min, Nuclei = 20 min, testssl = 10 min.

---

## 15. Observability and audit

### 15.1 Structured logging

Every log line is JSON. Required fields: `timestamp`, `level`, `logger`, `message`, `correlation_id` (scan_id or request_id), `organization_id` when known. Logs flow to Loki in prod; to stdout in dev.

### 15.2 Metrics (Prometheus)

Named metrics (not exhaustive):
- `zynksec_scans_total{status, intensity}`
- `zynksec_scan_duration_seconds{intensity}`
- `zynksec_scanner_runs_total{scanner, status}`
- `zynksec_scanner_duration_seconds{scanner}`
- `zynksec_findings_produced_total{severity, scanner}`
- `zynksec_false_positive_clicks_total{scanner, rule_id}`
- `zynksec_verification_attempts_total{method, status}`
- `zynksec_api_requests_total{endpoint, status}`

### 15.3 Tracing (OpenTelemetry)

Every scan is a trace. Spans: `orchestrator.prepare` → `fingerprint.detect` → `scanner.zap.run` / `scanner.nuclei.run` (parallel) → `orchestrator.normalize` → `orchestrator.correlate` → `orchestrator.prioritize` → `orchestrator.finalize`. Traces go to Tempo (free, self-hosted).

### 15.4 Audit log (separate from ops logs)

Every user-visible action writes a row into `audit_log`. Surfaced in the UI as a per-organization timeline. Audit log is **never** truncated; retained indefinitely.

Actions recorded include: project create/delete, target add/remove, verification attempt, scan start/cancel, finding status change, member invite/remove, API key create/revoke, settings change.

### 15.5 The internal scan inspector

An admin-only view where you (as the developer/operator) can open any past scan and see: every state transition, every scanner run, every raw finding with its normalizer output, every dedupe decision, every score adjustment. This is your primary debugging tool — build it in Phase 1.

---

## 16. Configuration management

### 16.1 Sources (in precedence order)

1. Environment variables (highest precedence).
2. SOPS-encrypted YAML files (committed, encrypted with age keys).
3. Default values in code.

### 16.2 Configuration surface

Grouped logically:

- **Database**: DSN, pool size, timeouts.
- **Redis**: DSN.
- **Object store**: endpoint, bucket, credentials.
- **GitHub OAuth**: client ID + secret.
- **SMTP**: email sender, creds.
- **Scanner configs**: per-scanner image tags, default timeouts, rate limits.
- **Feature flags**: per-phase toggles (e.g., `enable_ai_layer`).
- **Scoring weights**: tunable prioritizer weights.
- **Privacy**: retention windows for evidence, raw output.

### 16.3 Secrets

- Dev: `.env.local` (gitignored).
- Prod: SOPS-encrypted YAML with age public keys; only the operator's age private key can decrypt.
- Rotated by re-encrypting the file and redeploying. No rotation tooling in Phase 1 beyond that.

---

## 17. Security posture of Zynksec itself

Our own tool being compromised is the worst possible outcome. Hard-enforced from Phase 0:

- Scanner workers cannot reach the API, DB, or Redis. Enforced via Docker networks (dev) and NetworkPolicies (prod).
- Egress from scanner zone gated by Caddy reverse-proxy allowlist.
- Database is not reachable from the public internet at any point. Only the API can talk to it.
- All outbound calls from the API (GitHub, email, DNS for verification) go through an egress allowlist.
- Secrets are never logged. A log-sanitization middleware redacts known secret patterns before a log line leaves the process.
- Zynksec's own CI runs Semgrep + Gitleaks + Trivy on every PR (dogfooding).
- Zynksec's own frontend ships with perfect security headers: strict CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Zynksec's own Terms of Service include an authorization clause; signup gate enforces acceptance.
- Public `security.txt` at `/.well-known/security.txt` with disclosure instructions from Phase 1.

---

## 18. API surface (high-level)

Full OpenAPI spec lives in `docs/openapi.yaml` (generated from FastAPI) once code exists. The shape of the surface:

| Resource | Endpoints |
|---|---|
| Auth | `GET /auth/github/start`, `GET /auth/github/callback`, `POST /auth/logout`, `GET /auth/me` |
| Organizations | `GET/POST /organizations`, `GET/PATCH/DELETE /organizations/:id`, `GET/POST /organizations/:id/members` |
| Projects | `GET/POST /projects`, `GET/PATCH/DELETE /projects/:id` |
| Targets | `GET/POST /projects/:id/targets`, `GET/PATCH/DELETE /targets/:id`, `POST /targets/:id/verify` |
| Verifications | `GET /targets/:id/verifications`, `POST /targets/:id/verifications/recheck` |
| Scans | `GET/POST /targets/:id/scans`, `GET /scans/:id`, `POST /scans/:id/cancel` |
| Findings | `GET /projects/:id/findings`, `GET /findings/:id`, `PATCH /findings/:id`, `POST /findings/:id/verify` |
| Templates | `GET /remediation-templates`, `GET /remediation-templates/:zynksec_id` |
| Reports | `GET /scans/:id/report.pdf`, `GET /scans/:id/report.json`, `GET /scans/:id/report.sarif` |
| Webhooks (incoming) | `POST /webhooks/vercel`, `POST /webhooks/github` |
| Webhooks (outgoing) | configured per-project; signed with HMAC |
| Admin | `GET /admin/scan-inspector/:scan_id`, `GET /admin/audit-log` |
| Health | `GET /healthz`, `GET /readyz`, `GET /metrics` |

All JSON. All versioned under `/api/v1`. All endpoints documented and typed via FastAPI + Pydantic.

---

## 19. Error handling and user-facing feedback

### 19.1 Error taxonomy

Internal errors are classified at the boundary:

- `ClientError` — user input invalid; HTTP 4xx with a human-friendly message.
- `AuthorizationError` — user is not allowed; HTTP 403.
- `TargetUnreachableError` — scan target can't be reached; scan marked `FAILED` with actionable guidance.
- `ScannerError` — scanner failed; ScannerRun marked failed; scan continues with other scanners.
- `SystemError` — bug; HTTP 500; captured to error tracker (self-hosted GlitchTip, free).

### 19.2 User-facing guidance

Every error state has a known remediation message. "ZAP couldn't reach the target" says *check your target is online and firewall allows traffic from 1.2.3.4* — not a stack trace.

---

## 20. Migration and versioning strategy

- **Database**: Alembic migrations, single linear history. Every migration reviewed; no auto-generated migrations shipped without inspection.
- **Finding schema**: explicitly versioned (`schema_version` field). Breaking changes bump the version and trigger a backfill migration.
- **API**: `/api/v1` prefix. v2 would coexist, not replace.
- **Scanner versions**: pinned in config. Scanner upgrades are intentional: test against benchmark suite, then bump.
- **Rule/profile versions**: each rule and each profile carries a version string; rule runs record which version produced the finding.

---

## 21. How this maps to the roadmap

The scoping doc's phases correspond to specific architecture deliverables:

| Phase | Architecture work |
|---|---|
| 0 | Repo scaffolding, Docker Compose, Postgres migrations for the core tables (`organizations`, `users`, `projects`, `targets`, `scans`, `scanner_runs`, `raw_findings`, `findings`, `finding_evidence`), ZAP plugin implementation, fingerprinter skeleton, scan state machine end-to-end (empty profile). |
| 1 | Nuclei plugin, testssl plugin, Next.js+Vercel profile, remediation templates (markdown), finding schema v1, correlator, prioritizer, basic dashboard, GitHub OAuth, ownership verification (DNS + well-known), audit log. |
| 2 | ProjectDiscovery recon plugins, Interactsh integration, authenticated scans (ZAP auth scripts), OpenAPI ingestion, Deep intensity, post-fix verification, PDF snapshot report. |
| 3 | Repo targets, Phase 3 scanners (Semgrep, Gitleaks, Trivy, OSV, Syft, Grype), cross-correlation (DAST+SAST), repo fingerprinting. |
| 4 | Garak/PyRIT integration, AI endpoint discovery, prompt-injection probes, denial-of-wallet measurement. |
| 5 | Community rule packs, API keys, RBAC expansion, beta onboarding tooling. |
| 6 | AI amplification layer (local Mistral/Qwen3), contextual remediation notes, semantic dedupe pass. |
| 7 | Kubernetes migration, SSO, compliance mappings, runtime protection as a separate product. |

