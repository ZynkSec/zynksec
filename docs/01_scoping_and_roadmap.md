# Zynksec — Product Scoping & Roadmap (v0.2)

**Owner:** Hugo Herrera
**Status:** Draft for review (v0.2 — pivot from v0.1)
**Date:** 2026-04-19

---

## 0. What changed from v0.1

Hugo's answers to the open questions triggered a meaningful pivot. The new version of the plan reflects five decisions:

1. **Name is final** — Zynksec; domain already owned.
2. **No deadline, personal project first** — so the plan is sequenced for correctness and learning, not speed-to-market.
3. **Solo builder** — the architecture has to be maintainable by one person; no microservice sprawl, no Kubernetes until it's unavoidable.
4. **No budget** — every component must be free and self-hostable. The AI amplification layer is **moved to the final phase**, not the MVP. When it arrives, it starts on self-hosted open-weight models (Mistral Small, Qwen3) so it stays free.
5. **MVP scope pivots from Path B (repo scanning) to Path A (DAST — live web/API scanning).** Hugo's explicit target vulnerabilities — SQLi, XSS, CSRF, Broken Access Control, Security Misconfig, Insecure APIs, SSRF — are primarily detected by testing running applications, plus Hugo explicitly named OWASP ZAP as the core engine. Repo scanning (SAST, secrets, deps) is reclassified as a **companion track in Phase 3**, not the starting point.

## 1. One-line product definition

Zynksec is an **open-source security platform that safely runs automated attack simulations against a user's live web app or API, detects real vulnerabilities, and explains them clearly enough for the app owner to fix them.**

The wedge: the explosion of AI-assisted / "vibe-coded" SaaS products has created a generation of apps that ship fast but ship insecure. Existing DAST tools (Burp Suite Pro, Invicti, StackHawk) are priced and designed for security teams. Zynksec is built for the **founder or small-team owner** of a modern SaaS who needs to find and fix the issues *before someone else does*, using fully open-source tooling so nothing is gatekept behind enterprise licensing.

## 2. Target vulnerability coverage (the MVP promise)

Every vulnerability on Hugo's list maps to a concrete detection strategy using free engines:

| Vulnerability class | How Zynksec detects it |
|---|---|
| **SQL injection** | ZAP active scan rules (error-based, boolean-based, time-based); Nuclei SQLi templates; later Semgrep tainted-flow rules when repo is connected. |
| **Cross-site scripting (reflected, stored, DOM)** | ZAP active scan (all three variants); Nuclei XSS templates; header checks for missing CSP. |
| **Cross-site request forgery** | ZAP CSRF-token detection; passive checks for missing `SameSite` cookies; detection of state-changing GET endpoints; custom Nuclei templates. |
| **Broken access control (incl. IDOR, BFLA)** | Multi-role authenticated crawl (ZAP contexts + scripts) then comparison of what each role can reach; detection of sequential/UUID object IDs on privileged endpoints; OpenAPI-driven authorization matrix tests. |
| **Security misconfiguration** | ZAP passive scan (missing security headers, verbose errors, directory listing); `testssl.sh` / `sslyze` for TLS issues; Nuclei exposure templates (`.git`, `.env`, default creds, admin panels). |
| **Insecure APIs (OWASP API Top 10)** | Ingest OpenAPI/GraphQL spec → drive ZAP API scan; custom Nuclei templates for BOLA, broken auth, unrestricted resource consumption, BFLA, mass assignment. |
| **Server-side request forgery** | ZAP active scan + **self-hosted Interactsh** as the out-of-band (OAST) interaction server to catch blind SSRF; Nuclei SSRF templates. |

Interactsh is critical: it's the free, self-hostable OOB server that makes blind SSRF and blind injection detectable. Without it we miss the attacks that never produce a response in the HTTP channel.

## 3. MVP scope — DAST-first, hosted

### 3.1 In scope for MVP (v1.0)

- **Target onboarding:**
  - User adds a target by URL.
  - Mandatory ownership verification (DNS `TXT` record or well-known file, like Google Search Console) before any active scan runs. Passive scans may run on unverified targets.
  - Optional: upload OpenAPI / GraphQL schema to enable API scanning.
- **Scan pipeline** with ZAP at the center:
  - Stage 1 — Recon (optional): Subfinder (subdomains), httpx (live hosts), Katana (crawl), Naabu (ports). Only runs on user-verified apex domains.
  - Stage 2 — Passive scan: ZAP baseline scan + `testssl.sh`.
  - Stage 3 — Active scan: ZAP Automation Framework YAML plan + Nuclei templates.
  - Stage 4 — OOB checks: Interactsh webhook listens for callbacks triggered by SSRF/injection payloads.
- **Authenticated scans** (critical for access-control coverage): ZAP auth scripts supporting form login, JWT, OAuth2, cookie auth.
- **Unified finding schema** — every engine's output normalized into `{id, type, severity, confidence, title, evidence, location, remediation, exploitability_signals}`.
- **Correlation + dedupe** — when ZAP and Nuclei report the same issue, they become one finding with higher confidence.
- **Prioritization** — severity × exploitability (KEV / EPSS when applicable) × auth-required flag × asset criticality.
- **Plain-language remediation** — in MVP this comes from **curated markdown templates per vuln class**, not AI. Templates are good enough to ship; AI comes in Phase 6 to make them contextual.
- **Dashboard** — target list, scan history, findings list with filters, per-finding detail page with evidence + fix guidance.
- **Scheduled rescans** — cron-based (daily/weekly).
- **Export** — JSON, SARIF, and a PDF "security snapshot" report.

### 3.2 Out of scope for MVP (explicit)

- AI-generated explanations or fixes — **deferred to Phase 6**.
- Repo scanning (SAST, secrets, dependencies, SBOM) — deferred to Phase 3 as a companion track.
- Runtime protection / WAF — deferred to Phase 7 (Coraza + OWASP CRS).
- IaC / Kubernetes / container image scanning — deferred.
- Enterprise features (SSO, audit logs, RBAC, compliance mappings) — post-launch.
- Automated exploitation of any kind — **permanently out of scope**. Zynksec detects, it doesn't exploit.
- Autonomous agents that take write actions on user infrastructure — **permanently out of scope**.

### 3.3 Reliability targets for the MVP

- A full scan of a medium-sized web app completes in under 60 minutes.
- False-positive rate below 25% on the high-severity bucket, measured against the internal benchmark lab (see §6).
- Zero false negatives on a baseline set of known issues in DVWA and OWASP Juice Shop. If the scan misses a known SQLi in Juice Shop, CI breaks.

## 4. Technology stack (100% free + self-hostable)

**Decision: Python 3.12 + FastAPI + Celery + Redis + PostgreSQL + Next.js. All scanners run as Docker containers.**

Why Python over Go even though ZAP is Java and several other scanners are Go: every scanner is invoked as a subprocess or over HTTP, so the orchestrator's language doesn't affect integration. Python gives fastest dev velocity for a solo builder, has excellent libraries for HTTP/async/background jobs, and keeps the door open for the eventual AI layer (where Python's ecosystem is unmatched).

| Layer | Choice | Cost |
|---|---|---|
| API | FastAPI (Python 3.12) | Free |
| Job queue | Celery + Redis | Free |
| Scanner workers | Docker containers, one image per engine | Free |
| DB | PostgreSQL 16 | Free |
| Object storage | Local filesystem → MinIO (self-hosted S3) when multi-node | Free |
| Frontend | Next.js 14 + Tailwind + shadcn/ui | Free |
| Auth | Auth.js + GitHub OAuth (or magic links via SMTP) | Free |
| OOB server | Self-hosted Interactsh | Free |
| TLS checks | `testssl.sh` or `sslyze` | Free |
| Observability | Prometheus + Grafana + Loki (self-hosted) | Free |
| Infra (dev) | Docker Compose on your laptop | Free |
| Infra (hosted) | 1× Hetzner CAX11 ARM VPS when you need it | ~€3.85/mo |
| Domain | zynksec (already owned) | Sunk cost |
| LLMs | None until Phase 6; then local Mistral Small / Qwen3 on own hardware | Free |

**Total recurring cost to reach the beta milestone: €0 if running on your laptop, or ~€5/mo if you move to a VPS. No other paid dependencies.**

### Repo structure (proposed)

```
zynksec/
├── apps/
│   ├── api/              # FastAPI service
│   ├── web/              # Next.js frontend
│   └── worker/           # Celery workers
├── packages/
│   ├── scanners/         # One module per engine: zap, nuclei, subfinder, httpx, katana, naabu, testssl
│   ├── normalizer/       # Scanner output → unified finding schema
│   ├── correlator/       # Dedupe + confidence scoring
│   ├── prioritizer/      # Severity × exploitability × reachability
│   └── templates/        # Remediation markdown per vuln class (v1) + Nuclei/ZAP rule packs
├── infra/
│   ├── docker-compose.yml        # Local dev
│   ├── docker-compose.targets.yml # Attack lab (DVWA, Juice Shop, bWAPP, WebGoat)
│   └── helm/                      # Kubernetes charts (Phase 7+)
└── docs/
```

## 5. Architecture at a glance

```
                 ┌──────────┐
                 │ Next.js  │  (dashboard, auth, target management)
                 └────┬─────┘
                      │ HTTPS
                 ┌────▼─────┐
                 │ FastAPI  │  (REST + scheduled-scan triggers)
                 └────┬─────┘
                      │ enqueue
                 ┌────▼─────┐      ┌──────┐
                 │  Celery  │◄────►│Redis │
                 │dispatcher│      └──────┘
                 └────┬─────┘
     ┌────────────────┼────────────────┬────────────────┐
     ▼                ▼                ▼                ▼
┌─────────┐     ┌─────────┐      ┌─────────┐      ┌───────────┐
│  ZAP    │     │ Nuclei  │      │ Recon   │      │ testssl.sh│
│(Docker) │     │(Docker) │      │suite    │      │(Docker)   │
└────┬────┘     └────┬────┘      └────┬────┘      └─────┬─────┘
     │               │                │                 │
     └───────┬───────┴────────┬───────┴─────────────────┘
             │                │
             ▼                ▼
       ┌──────────┐     ┌────────────┐
       │Normalizer│     │ Interactsh │  (OOB callbacks for SSRF/blind)
       └────┬─────┘     └─────┬──────┘
            ▼                 │
      ┌──────────┐            │
      │Correlator│◄───────────┘
      └────┬─────┘
           ▼
      ┌──────────┐
      │Prioritize│
      └────┬─────┘
           ▼
      ┌──────────┐
      │Templates │  (curated fix guidance per class — no LLM in MVP)
      └────┬─────┘
           ▼
    ┌────────────────┐
    │Postgres + files│
    └────────────────┘
```

This is the same six-layer pipeline from the research doc (ingestion → discovery → execution → normalization → prioritization → presentation), but specialized for DAST.

### Scanner execution isolation (production safety)

Scanner workers run in a dedicated Docker network (or Kubernetes namespace, later) with these guardrails:

- Egress allowlist: workers can only reach `*.verified-target-domain` and `interactsh.zynksec.tld`; they cannot reach Zynksec's own API, DB, or internal services.
- Every scan has a hard CPU/memory limit and a wallclock timeout.
- Rate-limit outgoing requests per target (default: 20 req/s, tunable per target).
- All outgoing requests carry a `X-Scanner: Zynksec/1.0` header and a per-scan correlation ID so the target's ops team can see and block scans if needed.
- `robots.txt` is respected on passive scans by default (configurable).

## 6. Attack simulation environment — how we make this safe AND testable

There are **two distinct environments** covered by "secure attack simulation":

### 6.1 The dev-time target lab (for building Zynksec itself)

An isolated Docker Compose file spins up a collection of deliberately vulnerable apps on a private network:

- **OWASP Juice Shop** — modern Node.js app with a wide vuln catalog (SQLi, XSS, CSRF, IDOR, SSRF, auth flaws).
- **DVWA** — classic PHP/MySQL playground with known-good rule fixtures.
- **OWASP WebGoat** — Java-based, great for auth/access-control scenarios.
- **bWAPP** — very broad, covers OWASP Top 10 plus business-logic cases.
- **VAmPI** — deliberately vulnerable REST API for testing the API-scan pipeline.
- **crAPI** — Completely Ridiculous API, great for API Top 10 coverage.

This network (`zynksec-targets`) has no route to the public internet or to your host's services. Zynksec's scanner workers can reach it for local testing.

**These apps become the benchmark test suite.** Every release must pass: "scan Juice Shop → expect ≥ N findings covering these classes" as a CI check. If a refactor breaks detection, the build fails.

### 6.2 The production scan environment (for real user targets)

This is the scanner-isolation network described in §5 above. The key point: **the dev-time target lab and the production scan environment are completely separate.** Dev-time lab can't leak into prod; prod scanner can't reach dev-time lab.

## 7. Scalability architecture (solo-sized, but doesn't paint us into a corner)

The goal is: runs on a $5 VPS for MVP, same code scales to Kubernetes when there's demand and revenue. Achieved by three decisions:

- **Stateless API** — the FastAPI process holds no per-request state; scale horizontally behind a reverse proxy (Caddy or Traefik, both free) when needed.
- **Queue-driven workers** — scans are Celery tasks. Add a second worker node, it picks up jobs. No code changes required.
- **Database is the single source of truth** — every scan result, every finding, every user action writes to Postgres before anything else. If a worker dies, nothing is lost.

What we explicitly **do not do** in early phases:
- No Kubernetes.
- No service mesh.
- No multi-region deployment.
- No microservice split (the API is a monolith with internal modules).

Kubernetes becomes relevant in Phase 7 if demand justifies it. Everything else is over-engineering.

## 8. Revised roadmap (solo pace, no deadline)

Realistic solo cadence is nights + weekends. I'm using **months** instead of weeks, and setting each phase with an **exit criterion** you can self-verify.

### Phase 0 — Foundation (month 1)
- Scaffold the monorepo.
- Docker Compose up: FastAPI + Celery + Postgres + Redis running locally.
- Spin up the target lab (Juice Shop + DVWA).
- Run ZAP baseline scan **manually from the CLI** against Juice Shop — not yet integrated into the backend.
- **Exit:** you can hit an endpoint that enqueues a scan, and ZAP runs against Juice Shop, and the raw JSON lands in Postgres. No UI required.

### Phase 1 — Core DAST pipeline (months 2–4)
- ZAP Automation Framework YAML plans callable from the worker.
- Nuclei integration.
- Unified finding schema + normalizer for ZAP and Nuclei.
- Dedupe + priority scoring.
- First pass at curated remediation templates (one per vuln class on Hugo's list).
- Bare-bones Next.js dashboard: target list, scan history, findings list, finding detail.
- GitHub OAuth auth.
- **Exit:** you can sign in, add a pre-authorized test target, run a scan, see triaged findings.

### Phase 2 — Authenticated + API scanning (months 5–7)
- Ownership verification flow (DNS TXT).
- ZAP auth scripts (form, JWT, OAuth2).
- OpenAPI/GraphQL ingestion → ZAP API scan.
- Custom Nuclei templates for the OWASP API Top 10.
- Self-hosted Interactsh for blind SSRF/injection.
- `testssl.sh` integration.
- **Exit:** running Zynksec against crAPI or VAmPI detects ≥80% of known issues, including at least one blind SSRF via Interactsh.

### Phase 3 — Repo companion (months 8–9)
- GitHub App for repo read access.
- Semgrep, Gitleaks, Trivy, OSV-Scanner, Syft, Grype as additional workers.
- Cross-correlation: a SQLi flagged by ZAP in production + a Semgrep tainted-flow finding in the same endpoint = one high-confidence finding.
- **Exit:** repo + live target scan of the same project produces merged findings with cross-engine evidence.

### Phase 4 — Reliability + polish (months 10–11)
- Benchmark suite in CI against Juice Shop / DVWA / crAPI — build fails if detection regresses.
- PDF report export.
- Scheduled rescans + webhook-triggered rescans.
- Landing page on `zynksec` domain.
- **Exit:** dogfood-ready. You scan your own apps and those of friends without hand-holding.

### Phase 5 — Closed beta (months 12–14)
- Onboard 5–10 hand-picked beta users from indie-hacker / SaaS founder circles.
- False-positive feedback loop: every "not useful" click informs the prioritizer.
- **Exit:** <25% FP rate on high-severity bucket; beta NPS > 30.

### Phase 6 — AI amplification (when hardware allows)
- Self-host Mistral Small 3.1 or Qwen3 on your own workstation (one-time hardware cost, zero recurring).
- Use the model for: semantic dedupe, plain-language explanations personalized to the user's stack, contextual fix suggestions.
- All outputs cite the underlying scanner finding — no AI-invented findings, ever.
- **Exit:** AI explanations measurably improve user resolution rate vs the curated-template baseline.

### Phase 7 — Commercial viability (when and if)
- Pricing, Stripe, a public launch.
- Move from Docker Compose / single VPS to Kubernetes if load justifies it.
- Custom ZAP Java add-ons ONLY for specific business-logic or multi-tenant access-control tests not achievable with rules/templates. Writing Java add-ons is expensive solo work; defer until it's the right problem to solve.
- Runtime protection (Coraza + OWASP CRS) as a separate product line.

## 9. Top risks and mitigations

| Risk | Mitigation |
|---|---|
| Scope creep (solo + no deadline → infinite rebuilds) | Strict phase exit criteria. Don't leave a phase early or late. |
| False-positive flood kills trust | Benchmark suite in CI from Phase 4 onward; FP rate is a release-blocking KPI. |
| Custom ZAP Java add-ons consume months | Don't start until Phase 7 and only if rules/templates can't close the gap. |
| DAST being abused (user scans something they don't own) | Ownership verification is a hard gate from Phase 2. No scans allowed without it on non-lab targets. |
| Scanner hits production of real users and causes outages | Rate-limit + timeout + `X-Scanner` header + opt-in rescan schedule. Passive-only by default on initial scan; active scan requires explicit confirmation. |
| Legal exposure from scanning | Terms of service with mandatory authorization attestation. Audit log of every scan with the verifying user. |
| ZAP/Nuclei upgrades break pipelines | Pin Docker image versions; upgrade intentionally with regression tests. |
| Solo burnout | No deadline is a gift — use it. Ship Phase N before starting Phase N+1. |

## 10. Differentiation (still true in v0.2)

- **Open source and transparent** — users can see every rule we run, audit the Docker images we use, and self-host if they want.
- **Founder-priced, founder-friendly** — plain-language explanations, not CVE-dumps.
- **Curated-first, AI-later** — Zynksec works well before adding AI, which means AI never covers for weak detection. When AI arrives in Phase 6, it amplifies already-reliable findings.
- **Safe by construction** — ownership verification, isolated execution, no exploitation. Enterprise security leaders will trust it faster than flashier alternatives.

## 11. What you should do this week

1. **Lock the monorepo and initial Docker Compose** — FastAPI + Celery + Postgres + Redis running on your laptop.
2. **Stand up the target lab** — Juice Shop + DVWA on `zynksec-targets` network.
3. **Run ZAP baseline scan against Juice Shop manually from the command line.** Capture the JSON output. Look at it. Understand what ZAP gives you natively before writing any integration code.
4. **Draft a unified-finding-schema v0** on paper (or in a markdown doc). This is the contract the whole pipeline depends on — get it right before wiring anything.

Once those four are done, Phase 1 begins.

---
