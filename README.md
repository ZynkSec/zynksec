# Zynksec

> **Status: pre-alpha. Building in public. Not usable yet — do not point this at anything you care about.**

Zynksec is an open-source security platform for modern SaaS applications. The goal is to take the vulnerability-detection capabilities that today are locked inside expensive commercial tools and rebuild them as a DevSecOps-friendly platform anyone can self-host.

## What Zynksec is

Zynksec is a **DAST-first** (Dynamic Application Security Testing) platform: it tests running web apps and APIs from the outside, the way a real attacker would, and reports the issues it finds with evidence, remediation guidance, and a priority score you can actually trust.

Under the hood, Zynksec orchestrates best-in-class open-source scanners — [OWASP ZAP](https://www.zaproxy.org/) as the core DAST engine, [ProjectDiscovery](https://projectdiscovery.io/) tools for recon, [Nuclei](https://nuclei.projectdiscovery.io/) for templated checks, [Interactsh](https://github.com/projectdiscovery/interactsh) for out-of-band detection, and more.

The differentiation lives above the scanners:

- **Unified finding schema** so different engines speak one language.
- **Noise reduction and correlation** so you don't get 400 duplicates from three scanners finding the same bug.
- **Plain-language remediation** tied to what the tool actually observed, not a generic CWE pamphlet.
- **Framework-aware scanning** — the first profile is Next.js + Vercel, a reality modern "vibe-coded" SaaS lives in.
- **Ownership verification** before any active scan, so the project cannot be weaponized against third parties.

Later phases add SAST, secret scanning, dependency / SBOM analysis, runtime protection, and an AI-assisted remediation and triage layer (self-hosted, open-weight models first).

## Why this exists

Modern SaaS is built faster than ever — Next.js + Vercel + Supabase + Clerk + Stripe can turn a weekend idea into production in hours. That speed usually outruns security. The commercial tools that address this cost tens of thousands of dollars per year and are built for large enterprises, not indie builders or early-stage teams.

Zynksec is the tool a solo founder, a small team, or a security-curious developer should be able to reach for on day one — free, self-hostable, and aimed at the security mistakes modern stacks actually make.

## Current status

| Phase | Scope | State |
| --- | --- | --- |
| Phase 0 — Foundation | Monorepo layout, Docker Compose, minimal ZAP baseline scan against a local target | In progress |
| Phase 1 — DAST MVP | ZAP orchestration, Nuclei integration, unified finding schema, basic UI, ownership verification | Planned |
| Phase 2 — Recon + APIs | Subfinder/httpx/Katana discovery, OpenAPI/GraphQL testing, OAST via Interactsh | Planned |
| Phase 3 — SAST / secrets / deps | Semgrep, Gitleaks, Trivy, OSV-Scanner, Syft, Grype | Planned |
| Phase 4 — AI-assisted remediation | Self-hosted open-weight models (Mistral Small 3.1, Qwen3 class) | Planned |
| Phase 5 — Hosted scan orchestration | Single-VPS deployment, multi-tenant hosted option | Planned |
| Phase 6 — Active defense | Coraza/ModSecurity + CRS, Falco for runtime | Planned |
| Phase 7 — Commercial viability | Pro rule packs, hosted SaaS, enterprise features | Planned |

Detailed scoping and roadmap lives in [`docs/01_scoping_and_roadmap.md`](docs/01_scoping_and_roadmap.md).

## Architecture at a glance

- **Backend:** Python 3.12, FastAPI, Celery, Redis, PostgreSQL.
- **Frontend:** Next.js, Tailwind, shadcn/ui, Auth.js + GitHub OAuth.
- **Scanners:** containerized workers (OWASP ZAP, Nuclei, ProjectDiscovery suite, etc.).
- **Deployment:** Docker Compose for local dev, single cheap VPS for Phase 5, Kubernetes only when there's a reason.
- **Schema:** Alembic migrations over a custom PostgreSQL schema — not DefectDojo.

Full architecture in [`docs/03_architecture.md`](docs/03_architecture.md).

## How to follow along

Zynksec is not ready for use or contribution yet. If you're curious:

- **Star the repo** to get notified when things start shipping.
- **Watch → Custom → Releases** to get pinged on the first usable release.
- **Discussions** are open for ideas, use cases, and questions.
- **Issues** are for bugs and scoped work once Phase 0 lands; please don't file implementation requests yet.

## Documentation

| Doc | What it covers |
| --- | --- |
| [`docs/01_scoping_and_roadmap.md`](docs/01_scoping_and_roadmap.md) | Product scope, phases, deployment topology, risk mitigation |
| [`docs/02_product_strength_and_foundations.md`](docs/02_product_strength_and_foundations.md) | Modern SaaS reality, expanded vulnerability taxonomy, design moves |
| [`docs/03_architecture.md`](docs/03_architecture.md) | System architecture, schemas, plugin contract, state machine |

## Security

Please don't file security issues as public issues. See [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Short version: Zynksec isn't ready for code contributions yet; the most helpful thing right now is to open a Discussion about the SaaS stack or vulnerability class you'd want Zynksec to handle best.

## License

Zynksec is licensed under the **GNU Affero General Public License v3.0**. See [`LICENSE`](LICENSE).

AGPLv3 was chosen deliberately: if someone runs a modified version of Zynksec as a hosted service, they must release their modifications under the same license. This keeps the open-source project durable against commercial forks that would otherwise absorb community work without giving anything back.

## Acknowledgements

Zynksec stands on the shoulders of OWASP ZAP, ProjectDiscovery, Semgrep, Trivy, OSV-Scanner, Coraza, Falco, and many others. Those projects are the reason this is possible at all.
