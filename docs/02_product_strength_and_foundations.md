# Zynksec — Product Strength & Foundations

**Owner:** Hugo Herrera
**Status:** Strategic companion to `01_scoping_and_roadmap.md` (v0.2)
**Date:** 2026-04-19

---

## Purpose of this document

The scoping doc answers *"what will we build first?"*. This doc answers three harder questions: *"what does it take to be the best tool for newer SaaS?"*, *"what foundations keep us reliable as we grow?"*, and *"what strategic choices must be made now so the foundations don't crack later?"*.

Your initial vuln list (SQLi, XSS, CSRF, broken access control, security misconfig, insecure APIs, SSRF) is a solid baseline — every competent DAST finds those. The opportunity is to go beyond that baseline in two specific directions: **coverage that matches how modern SaaS is actually built**, and **engineering foundations that make the findings trustworthy**. Trust is what Snyk, StackHawk and Aikido are really selling, not scan engines.

---

## Part 1 — Understanding the target: what "newer SaaS" actually looks like in 2026

If we optimize Zynksec for the SaaS archetypes of 2015 (monolithic Rails on a VPS), we'll ship a tool nobody needs. Modern SaaS — especially AI-built SaaS — has a very specific shape, and the vulnerabilities follow from that shape.

**Typical newer SaaS stack:**

- Frontend: Next.js or SvelteKit on Vercel/Netlify/Cloudflare Pages
- Backend: serverless functions (Vercel, Cloudflare Workers, AWS Lambda) or a thin Node/Python API
- Database: Supabase, Firebase, Neon, PlanetScale — schema managed by the dev via dashboard, not migrations
- Auth: Clerk, Auth.js, Supabase Auth, Firebase Auth — rarely rolled by hand
- Payments: Stripe (with webhooks)
- AI features: an OpenAI/Anthropic/Gemini call behind an API route, often with user-controlled prompts
- Third-party SDKs shipped to the browser: analytics, Intercom, Sentry, feature flags
- Infra-as-config: `vercel.json`, `wrangler.toml`, `supabase/config.toml` in the repo
- Deployment: every PR gets a preview URL, every preview URL has real env vars

**What this means for Zynksec:**

The most dangerous vulnerabilities in this archetype are often *not* classic SQLi or reflected XSS. They're:
- Secrets accidentally exposed to the client bundle (a `SUPABASE_SERVICE_ROLE_KEY` that leaks because it wasn't prefixed right)
- Supabase/Firebase row-level security rules that are too permissive
- Stripe webhook endpoints without signature verification (so anyone can POST `invoice.paid`)
- Preview deployments with production env vars and no auth in front of them
- Prompt injection in AI features that then has access to user data
- Clerk/Auth.js session tokens readable from a non-HTTP-only cookie
- Unbounded LLM API calls billed to the SaaS owner (denial of wallet)
- GraphQL or tRPC endpoints without auth guards on mutations
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`

None of those are in the OWASP Top 10 by name. All of them come up in nearly every real audit of a modern SaaS. **This is the territory where Zynksec wins.**

---

## Part 2 — Expanded vulnerability taxonomy

Below is the full catalog I recommend Zynksec grow into. It's grouped by category with a realistic "when do we ship it" column. The categories marked **Phase 1** are baseline; the rest are where Zynksec earns its differentiation.

### 2.1 Authentication & session

| Issue | Detection approach | Phase |
|---|---|---|
| Missing MFA / weak MFA | Test login flow for MFA presence; check session cookies for persistence bypass | 2 |
| JWT: `alg=none`, weak secret, algorithm confusion | Send forged JWTs during authenticated scans; brute-test common secrets | 2 |
| Session fixation / missing rotation on privilege change | Compare session IDs before/after login | 2 |
| Tokens in URLs (leak via referer/logs) | Crawl + check URLs for token-like parameters | 1 |
| Cookie flags: missing `HttpOnly`, `Secure`, `SameSite` | Passive scan | 1 |
| Email enumeration (different response for "user exists") | Register + login probes comparing timing and messages | 2 |
| Password reset token predictability / reuse | Request two resets, compare entropy | 2 |
| OAuth redirect_uri validation flaws | Probe registered vs arbitrary redirects | 2 |
| OAuth linking attacks (account takeover via pre-registered email) | Flow simulation (dangerous — opt-in only) | 3 |

### 2.2 Access control

| Issue | Detection approach | Phase |
|---|---|---|
| IDOR — direct object reference with predictable IDs | Authenticated multi-user crawl, attempt cross-user access | 2 |
| BOLA (API-level IDOR) | OpenAPI-driven authorization matrix across user roles | 2 |
| BFLA — broken function-level authorization | Probe admin endpoints as non-admin | 2 |
| Tenant isolation bypass (multi-tenant SaaS) | Two-tenant test accounts with cross-tenant probes | 3 |
| Missing auth on GraphQL mutations | Introspection + unauthenticated mutation probes | 2 |
| Missing auth on tRPC/REST endpoints | Enumeration + unauthenticated probes | 2 |
| Row-level security misconfig (Supabase/Firebase) | Requires connector; probe data visibility with a test user | 3 |

### 2.3 Injection (broadly)

| Issue | Detection approach | Phase |
|---|---|---|
| SQL injection | ZAP active scan + Nuclei | 1 |
| NoSQL injection (MongoDB, Firestore) | ZAP NoSQL rules + custom payloads | 2 |
| Command injection | ZAP active scan | 1 |
| Server-side template injection (SSTI) | Nuclei templates + polyglot payloads | 2 |
| Prototype pollution (JS backends) | Targeted payloads on JSON inputs | 3 |
| XPath/LDAP injection | ZAP rules | 2 |
| GraphQL injection + depth/complexity DoS | Introspection + crafted queries | 2 |
| Log injection (CRLF) | Passive header injection tests | 2 |

### 2.4 Cross-site issues

| Issue | Detection approach | Phase |
|---|---|---|
| Reflected / stored / DOM XSS | ZAP active scan (all three) | 1 |
| CSRF on state-changing endpoints | ZAP + custom checks for `SameSite` / token | 1 |
| Clickjacking (missing `X-Frame-Options` / `frame-ancestors`) | Passive scan | 1 |
| CORS misconfig (`*` + credentials, reflected origin) | Probe with varied `Origin` headers | 1 |
| PostMessage origin validation flaws | JS static analysis (repo mode) | 3 |

### 2.5 SSRF and out-of-band

| Issue | Detection approach | Phase |
|---|---|---|
| Classic SSRF (response visible) | ZAP active + Nuclei | 1 |
| Blind SSRF | **Self-hosted Interactsh** as OOB server | 2 |
| Cloud metadata endpoint SSRF (`169.254.169.254`) | Nuclei templates, dedicated payload set | 2 |
| Webhook-based SSRF (user supplies callback URL) | Probe webhook endpoints with internal URLs | 3 |

### 2.6 Security misconfiguration

| Issue | Detection approach | Phase |
|---|---|---|
| Missing security headers (CSP, HSTS, X-Content-Type-Options) | Passive scan | 1 |
| Verbose errors / stack traces | Trigger errors + pattern-match responses | 1 |
| Exposed files (`.git`, `.env`, `.DS_Store`, backups) | Nuclei exposure templates | 1 |
| Default credentials on admin panels | Nuclei default-cred templates | 1 |
| Debug endpoints in production (`/phpinfo`, Laravel `debug`, Rails console) | Nuclei + path brute | 1 |
| Directory listing | Passive | 1 |
| TLS issues (weak ciphers, old TLS, cert mismatch) | `testssl.sh` / `sslyze` | 1 |

### 2.7 Cryptography

| Issue | Detection approach | Phase |
|---|---|---|
| Weak TLS / cipher suites | `testssl.sh` | 1 |
| Weak hashes for passwords (MD5, SHA1) | Code scan mode | 3 |
| Predictable randomness (non-crypto RNG) | Code scan mode | 3 |
| Hardcoded keys / IVs | Gitleaks + Semgrep | 3 |
| Insecure JWT library defaults | Semgrep | 3 |

### 2.8 Rate limiting & resource consumption (big value for newer SaaS)

| Issue | Detection approach | Phase |
|---|---|---|
| No rate limit on login | Burst login attempts, measure | 2 |
| No rate limit on expensive ops (search, exports, PDF gen, AI calls) | Targeted bursts per endpoint | 2 |
| Unbounded pagination | Probe for `limit` / `per_page` | 2 |
| GraphQL complexity / depth DoS | Introspection + nested query probes | 2 |
| File upload size limits | Probe with large files (configurable) | 2 |
| Denial of wallet on AI endpoints | Identify AI-backed endpoints, probe cost envelope | 3 |

### 2.9 Data exposure & privacy

| Issue | Detection approach | Phase |
|---|---|---|
| PII in responses / error messages | Pattern-match for SSNs, emails, CC numbers | 2 |
| Stack trace in response | Passive scan | 1 |
| Source-map exposure in production | Fetch `.map` files, detect presence | 2 |
| Sourcemap → secret recovery | Extract bundled source, grep for secrets | 2 |
| GraphQL introspection enabled in production | Probe `__schema` | 2 |
| Backup files / `.bak` / `~` / `.old` | Path brute + Nuclei | 1 |

### 2.10 Client-side & bundle analysis (huge for newer SaaS)

| Issue | Detection approach | Phase |
|---|---|---|
| Secrets in client bundle (`NEXT_PUBLIC_*` with sensitive values, Supabase service keys) | Fetch bundle JS, regex + entropy scan | 2 |
| Exposed debug/admin flags in bundle | Pattern match | 2 |
| Outdated frontend libraries with known CVEs | Extract package names/versions from bundle, cross-check OSV | 2 |
| Missing Subresource Integrity on CDN scripts | Passive | 2 |
| Third-party script sprawl (unauditable analytics/chat widgets) | Catalog + flag | 3 |
| Source map exposing proprietary logic | Passive | 2 |

### 2.11 Webhook security (specific to SaaS that integrate with Stripe/GitHub/Slack)

| Issue | Detection approach | Phase |
|---|---|---|
| Webhook endpoint without signature verification | Send forged payload, expect rejection | 3 |
| Webhook replay attack vulnerability | Send same payload twice | 3 |
| Webhook endpoint accepts arbitrary origins | Check `Host` / `Origin` validation | 3 |

### 2.12 Cloud / preview / deployment hygiene

| Issue | Detection approach | Phase |
|---|---|---|
| Subdomain takeover (dangling DNS) | Subfinder + httpx + fingerprint response | 2 |
| Preview deployment exposed to internet (Vercel, Netlify) | Enumerate preview domains, probe auth | 3 |
| Open S3 / R2 / GCS buckets | Bucket enumeration on known domain patterns | 3 |
| Exposed Kubernetes / Docker / Consul / Redis | Nuclei misconfig templates | 2 |

### 2.13 Supply chain & dependencies (Phase 3 — the repo track)

| Issue | Detection approach | Phase |
|---|---|---|
| Known-CVE dependencies | OSV-Scanner + Trivy + Grype with KEV/EPSS | 3 |
| Typosquatting in package manifests | Custom check on manifest vs registry | 3 |
| Postinstall scripts in deps | Parse `package.json`/`pyproject.toml` | 3 |
| Unsigned / unverified dependencies | Sigstore verification where available | 3 |
| Exposed CI secrets (`GITHUB_TOKEN` leaks in Actions logs) | GitHub API read + Gitleaks on logs | 3 |
| GitHub Actions misconfigurations (pull_request_target, unpinned refs) | Semgrep rules for Actions | 3 |

### 2.14 **AI & LLM vulnerabilities (the 2026 moat)**

This is the category almost no mainstream AppSec tool covers well. For newer SaaS that all ship AI features, this is gold.

| Issue | Detection approach | Phase |
|---|---|---|
| **Prompt injection** (instruction override, data exfil via LLM) | Send adversarial prompts to discovered AI endpoints; check for instruction-follow leakage; use Garak / PyRIT payload libraries | 4 |
| **Insecure output handling** (LLM output rendered as HTML → XSS, rendered as SQL → injection) | Probe with HTML/script payloads in prompts; check response rendering | 4 |
| **Training / system prompt extraction** | Attempt system prompt leakage via known jailbreaks | 4 |
| **Sensitive data leakage** (LLM answers with other users' data) | Plant canary strings as one tenant, probe as another | 5 |
| **Over-permissioned tool/agent access** (agent can call arbitrary internal APIs) | Probe function-calling endpoints for tool scope | 5 |
| **Denial of wallet** (unbounded LLM calls cost money) | Measure cost per request, extrapolate attacker cost | 4 |
| **Model DoS via adversarial input** (payloads that make models loop) | Controlled-length test set | 5 |
| **MCP server misconfiguration** (exposed tools/resources, no auth) | Probe MCP endpoints, check permissions | 5 |

**Garak** (`nvidia/garak`) and **PyRIT** (Microsoft) are open-source LLM red-team frameworks you can wrap. Use them.

### 2.15 Business logic (hardest but highest-value)

| Issue | Detection approach | Phase |
|---|---|---|
| Race conditions on payments (TOCTOU) | Concurrent request bursts on transactional endpoints | 5 |
| Negative-value / overflow on prices/quantities | Fuzzing numeric inputs | 4 |
| Coupon stacking / promo abuse | Scripted business-flow tests per detected framework | 5 |
| Insecure Direct Object References in business flows | Part of access-control matrix | 2 |

### 2.16 Framework-specific profiles (the differentiation layer)

Zynksec should fingerprint the target's stack and run a **preset profile** with rules tuned to that stack. Generic scanners don't do this well. Profiles I recommend:

- **Next.js + Vercel** — check `_next/static/` for secrets, check for `pages/api/` or `app/api/` auth, check `vercel.json` config leaks, probe preview deployments.
- **Supabase** — test RLS policies with a guest and a user, check for exposed `service_role` key in bundle.
- **Firebase** — test Firestore rules, check for unauthenticated read, probe admin SDK exposure.
- **Clerk / Auth.js / Auth0** — check session cookie flags, probe sign-up lockout, validate JWT verification.
- **Stripe-integrated SaaS** — check webhook signature verification, check `client_reference_id` tampering.
- **Laravel / Django / Rails** — debug endpoint probes, default secret keys, known-insecure defaults.
- **tRPC / GraphQL** — schema introspection, per-procedure auth, depth limits.
- **AI-feature SaaS** — prompt injection probes, canary strings, cost envelope measurement.

Fingerprinting happens via `httpx` response headers, bundle analysis, favicon hash, and a small custom fingerprint DB. The profile then selects rules, auth flows, and probes.

---

## Part 3 — Foundations that keep us reliable

Coverage is one half. The other half is making findings trustworthy. A scanner that flags 1000 things of which 30 are real is worse than one that flags 30 things of which 25 are real. These foundations are how we stay on the right side of that tradeoff.

### 3.1 Evidence-first detection

Every finding in Zynksec must carry:

1. **Reproducer**: the exact request(s) that produced the evidence (curl-ready).
2. **Proof**: what in the response proves the vulnerability (a diff, a string match, an OOB callback, a timing delta).
3. **Location**: the URL, endpoint, and if available the file + line in the repo.
4. **Engine provenance**: which scanner/rule detected it, and any other engines that corroborate.

If a finding can't carry all four, we don't ship it.

### 3.2 The unified finding schema is the spine of the product

This is the single most load-bearing decision. Every scanner's output maps into one shared structure. Everything downstream — dedupe, prioritization, templates, UI, exports, AI layer — reads from this structure.

Proposed schema (v0):

```yaml
finding:
  id: uuid
  fingerprint: hash(type + location + payload-family)  # used for dedupe across scans
  type: cwe-id | owasp-id | internal-taxonomy-id
  title: short human title
  severity: info | low | medium | high | critical
  confidence: low | medium | high  # based on engine + corroboration
  evidence:
    - engine: zap | nuclei | semgrep | gitleaks | testssl | custom
      rule_id: string
      request: raw HTTP request
      response: raw HTTP response (truncated)
      proof: what makes this a hit
  location:
    url: string
    method: string
    parameter: string | null
    file: string | null  # repo mode
    line: int | null
  remediation:
    template_id: string  # curated markdown template id
    contextual_notes: string | null  # filled by AI in Phase 6
  exploitability:
    kev_match: bool
    epss_score: float | null
    auth_required: bool
    internal_only: bool
  first_seen: timestamp
  last_seen: timestamp
  status: open | triaged | fixed | accepted_risk | false_positive
  history: [ {timestamp, event, actor} ]
```

Put this schema in a single source of truth (e.g., a Pydantic model + JSON Schema export) and version it. Every migration matters.

### 3.3 Taxonomy discipline (CWE + OWASP + internal)

Every finding type gets mapped to:
- A CWE ID (the industry standard)
- An OWASP category (Top 10 or API Top 10)
- An internal Zynksec taxonomy ID (stable, human-readable — e.g., `ZS-AUTH-JWT-NONE`, `ZS-AI-PROMPTINJ-001`)

Why internal IDs matter: CWE is too broad, OWASP changes. Your own IDs let you version rules and remediation templates independently.

### 3.4 Severity framework (don't reinvent CVSS, but adapt it)

- Start by using CVSS v4 vector strings to derive a 0–10 score for every finding.
- Overlay with exploitability signals: KEV match → floor at High, active EPSS > 0.5 → floor at High.
- Apply a context multiplier when known: auth-required findings step down one level; findings on login/payment/admin endpoints step up.
- Surface the factors in the UI. Users trust scores they can audit.

### 3.5 The benchmark suite IS the product KPI

This has appeared in both docs, so I'll only add the piece that hasn't: make the benchmark a **live internal dashboard**. Every main-branch merge runs the full benchmark and publishes: precision, recall, per-category coverage, regression diff. When the dashboard goes red, no releases.

Recommended targets for the benchmark:
- OWASP Juice Shop (modern JS, broad catalog)
- DVWA (classic, stable)
- OWASP WebGoat (auth + access control)
- VAmPI (vulnerable REST API)
- crAPI (vulnerable API — API Top 10 coverage)
- OWASP BWA (virtual machine with many apps)
- A **purpose-built Zynksec test app** you write yourself, with synthetic instances of every vuln class you claim to cover. This is the one test bed you fully control.

### 3.6 Plugin architecture for scanners

Decide now on the shape of a "scanner plugin." Each scanner lives as a module in `packages/scanners/` and implements a common interface:

```python
class Scanner(Protocol):
    id: str
    version: str
    def supports(self, target: ScanTarget) -> bool: ...
    async def run(self, target: ScanTarget, config: dict) -> list[RawFinding]: ...
    def normalize(self, raw: RawFinding) -> Finding: ...
```

Adding a new engine = implementing one class + one Dockerfile + one YAML config. If adding a scanner ever takes more than a day, the plugin interface is wrong — fix it, don't add the scanner.

### 3.7 Feedback loop as a first-class system

Every finding in the UI needs two buttons that the product learns from:
- "Not a real issue" — trains the prioritizer to downweight this fingerprint.
- "Fixed this" — closes the finding and marks it for verification on next scan.

Store the raw signal. Aggregate by rule_id to produce a per-rule FP rate. When a rule's FP rate crosses a threshold, auto-demote its severity until reviewed. This is the mechanism that compounds over time.

### 3.8 Zynksec must be secure to be credible

An AppSec tool that gets compromised is a punchline. Rules I'd enforce from day one:

- Scanner workers can't reach the main API or DB.
- All secrets in Hashicorp Vault or a free alternative (SOPS + age keys for a solo dev — no cost).
- Every dependency upgrade is reviewed; lockfiles pinned.
- Zynksec scans itself in CI (dogfood).
- Public bug bounty page (no money, just recognition) from Phase 5.
- Security headers and cookies on your own frontend are perfect. If a vulnerability scanner's own site has missing CSP, that's embarrassing.

### 3.9 Observability from day one (not phase 5)

- Every scan emits structured logs with a correlation ID.
- Metrics: scans started, scans failed, per-scanner duration, findings per scanner.
- Traces for scan pipelines (OpenTelemetry → Grafana Tempo, free self-hosted).
- An internal "scan inspector" view where you can look at any past scan's full execution trace. This is the debugging tool you'll live in.

### 3.10 Audit trail (non-negotiable for a security tool)

Every action logged with who/what/when: scan started, target added, ownership verified, finding status changed, user invited, settings modified. Users will ask for this before they trust Zynksec with their apps. Build it early.

### 3.11 Legal + ethical scaffolding

Before the first external user ever signs up, you need:

- **Terms of Service** with explicit authorization clause: "by adding a target you attest you own it or are authorized to test it."
- **Ownership verification** as a hard enforcement, not a check-the-box. DNS TXT or well-known file, no scan without it.
- **Abuse response process**: what do you do if someone scans a target they don't own? How do you detect and block? (Rate-limit per user, flag repeated invalid verification attempts, cap parallel scans.)
- **Responsible disclosure guidance** for users: when Zynksec finds something in their own third-party dependency, what do they do? Link to coordinated-disclosure resources.
- **Data retention policy**: how long do you keep scan data? Evidence blobs? Users need to know.

None of these cost money. All of them need to exist before beta.

### 3.12 Documentation discipline (especially for a solo builder)

Three kinds of docs, treated as seriously as code:

1. **`docs/adr/`** — Architecture Decision Records. Every non-trivial choice gets a short doc: context, decision, consequences. Future-you will thank present-you.
2. **`docs/rules/`** — every detection rule has a page explaining what it checks, when it fires, how to verify, how to remediate. These pages become your public vuln encyclopedia later.
3. **`docs/runbooks/`** — "what to do when" docs. Worker stuck. Scan timing out. Postgres disk full. You're solo; these are your uptime.

ADRs especially: a decision you wrote down at the time is worth five decisions you try to remember six months later.

---

## Part 4 — Design moves specifically for newer-SaaS buyers

Coverage and foundations are invisible. These are the moves the user feels.

### 4.1 Framework fingerprinting + preset profiles

Already called out in §2.16. Worth repeating as a product move: when a user adds `myapp.com`, Zynksec should say within 30 seconds *"Detected Next.js 14 on Vercel with Supabase auth. Running the Next.js + Supabase profile."* That single line makes the tool feel smart and makes the findings list relevant.

### 4.2 The "security snapshot" report

A one-page PDF the founder can forward to a co-founder, a customer, or a sales prospect. Not a 50-page pentest report. Contents:

- Top 5 issues in plain language
- Risk score (0–100) with a clear trend line
- Coverage summary ("we tested X endpoints, Y auth flows, Z API routes")
- What's NOT covered (honesty builds trust)

### 4.3 Post-fix verification

When a user marks a finding as "fixed", Zynksec queues a targeted rescan of just that endpoint with just the original payload within minutes. The UI shows: "Fixed — verified by rescan at 14:22." This is the dopamine loop that keeps users engaged.

### 4.4 Change-driven scans

Integrate with GitHub so a scan runs on every deployment (via webhook from Vercel/Netlify/Cloudflare Pages → your API). Findings then track by commit, not by wallclock time. This is what Snyk's continuous-scanning moat looks like, built from free parts.

### 4.5 Educational layer

Every finding class has a short "learn" article — 3–4 paragraphs, no jargon, with one code example of the fix. This is work you can do gradually. It compounds: the articles become SEO, become a documentation moat, become the training data for Phase 6's AI layer.

### 4.6 Community rule packs

In Phase 5+, let external users contribute Nuclei templates or Semgrep rules that Zynksec can run. Gated on review; credited in release notes. This is how open-source security tools grow coverage faster than any proprietary vendor.

---

## Part 5 — Strategic decisions that need to be locked before Phase 1 code

These choices shape the foundations. Getting them wrong is expensive later.

### 5.1 License choice

Three options, in order of my recommendation for Zynksec:

1. **AGPLv3 for the code + proprietary rule packs + SaaS add-ons** (recommended) — lets you publish the source and build community trust while protecting your hosted offering. Anyone self-hosting must publish modifications. This is what GitLab, Grafana Labs, and many OSS-first companies use.
2. **MIT / Apache 2.0** — maximally permissive. Easier to attract contributors and casual users. Offers zero protection from a large competitor cloning Zynksec as a managed service.
3. **Source-available (BSL / Elastic License)** — lets people read code but not operate a competing service. Middle ground, but costs community goodwill.

AGPLv3 is my recommendation given you want OSS-first positioning and need moat protection.

### 5.2 How public are detection rules?

Proposal: **rules are public, rulepacks are layered.**

- Core rules (the OWASP Top 10 coverage) — public, in the main repo. Builds trust.
- SaaS-specific framework profiles (Next.js, Supabase, etc.) — public, but gated by signing in, so you get signup attribution.
- "Zynksec Pro" rule packs (business logic, framework-specific auth, AI checks) — private, shipped only to paying users in Phase 5+.

This mirrors how Semgrep handles it and lets you be genuinely open while keeping a commercial lane.

### 5.3 Scan intensity tiers

Offer three:
- **Passive** — runs without any active probes. Safe for any target, no ownership verification needed. Useful for early signup engagement.
- **Standard** — ZAP active scan + Nuclei + TLS + basic auth probes. Requires ownership verification. This is the default.
- **Deep** — adds OOB (Interactsh), fuzzing, business-logic probes, AI-feature probes. Requires ownership verification + explicit confirmation per scan. Longer runtime.

Defaulting users to "Standard" and letting them opt into "Deep" prevents accidental production impact.

### 5.4 Data retention + privacy posture

Lock this in writing now:

- Raw HTTP responses kept 30 days, then purged (they can contain user data).
- Findings metadata kept indefinitely.
- User can request full deletion at any time.
- Evidence blobs encrypted at rest (cheap with SOPS + age).
- No telemetry on scan content; only anonymous operational metrics.

This becomes a marketing point for privacy-sensitive SaaS customers.

### 5.5 Responsible scanning identity

Every scan request carries:
- `User-Agent: Zynksec/<version> (+https://zynksec/scanner-info)`
- `X-Scanner-Id: <scan-uuid>`
- Origin IP that resolves back to Zynksec and is listed at a public URL

If a target's ops team sees strange traffic, they can look up Zynksec and block or contact. This is the difference between a legitimate scanner and a low-rent one.

---

## Part 6 — How these additions fit the existing roadmap

The existing phases in `01_scoping_and_roadmap.md` don't need to be rewritten; they need to be *enriched*. Here's how the new coverage and foundations thread in:

- **Phase 0:** Add §3.1 (evidence-first), §3.2 (finding schema) and §3.3 (taxonomy) as design artifacts. No code, just agreed-upon formats.
- **Phase 1:** Framework fingerprinting (§2.16) ships with the first ZAP + Nuclei integration. Pick *one* profile to start (Next.js/Vercel).
- **Phase 2:** Add client-side bundle analysis (§2.10), rate-limiting probes (§2.8), and the full OOB setup with Interactsh (§2.5). Auth-awareness is this phase.
- **Phase 3:** Repo companion adds §2.13 (supply chain) and fills in §2.7 (crypto via SAST).
- **Phase 4:** First AI/LLM probes ship (§2.14) — prompt injection + denial of wallet. Pragmatic, Garak-wrapped.
- **Phase 5:** Community rule packs (§4.6), advanced business-logic checks (§2.15), deeper AI/agent/MCP coverage (§2.14).
- **Phase 6:** AI amplification layer arrives (as per v0.2 scoping doc).
- **Phase 7:** Commercial launch + K8s + runtime protection.

---
