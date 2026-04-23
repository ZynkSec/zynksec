# Contributing to Zynksec

Thanks for even opening this file. Zynksec is a solo, pre-alpha project building in public, and your interest genuinely matters.

## Current state: pre-alpha

**Zynksec is not yet ready for code contributions.** The architecture, schemas, and scanner plugin contract are still being finalized, and accepting pull requests before those land would create rework for everyone.

That said, there are high-value ways to help right now.

## How you can help today

1. **Share the SaaS stack you want Zynksec to scan well.**
   Open a [Discussion](https://github.com/ZynkSec/zynksec/discussions) describing the stack (e.g., Next.js + Vercel + Supabase + Clerk, or Django + Render + Auth0) and the vulnerability classes that stack tends to make easy to get wrong. Framework-aware scanning is a core design goal; your real-world experience makes the framework profiles useful.
2. **Name the vulnerability types Zynksec must not miss.**
   If you've shipped a SaaS and learned the hard way what a scanner _should_ have caught, we want to hear it. This shapes the benchmark suite.
3. **Review the design docs.**
   [`docs/01_scoping_and_roadmap.md`](docs/01_scoping_and_roadmap.md), [`docs/02_product_strength_and_foundations.md`](docs/02_product_strength_and_foundations.md), and [`docs/03_architecture.md`](docs/03_architecture.md) are the thinking so far. If something looks wrong, unclear, or missing, open an Issue with the `design-review` label.
4. **Star and watch.**
   Seriously — this is the clearest signal to keep going and the fastest way to get notified when Phase 0 is usable.

## How you can help once Phase 1 lands

- Code contributions (backend, frontend, scanner plugins).
- **Rule packs** — custom Nuclei templates, ZAP active scripts, correlation heuristics.
- **Benchmark entries** — intentionally vulnerable apps Zynksec should flag.
- Framework profiles for stacks Zynksec doesn't cover yet.
- Translations of the UI and remediation content.

We will publish contribution guidelines with issue labels, branching strategy, commit conventions, and DCO / CLA decisions before Phase 1 opens.

## Ground rules

- **Security issues do not go in public issues.** See [`SECURITY.md`](SECURITY.md).
- **Be kind.** See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). This is enforced.
- **Don't scan things you don't own.** Zynksec is a security tool. Misusing it is a crime in most jurisdictions. The project cannot and will not help with that.
- **AGPLv3.** Contributions are accepted under the project's AGPLv3 license. By opening a pull request you agree your contribution is licensed under AGPLv3.

## Development setup

Once Phase 0 lands, this section will be replaced with real setup instructions (Docker Compose spin-up, running tests against the target lab, etc.). For now, the fastest way to understand where things are going is to read the architecture doc.

## Questions

Open a [Discussion](https://github.com/ZynkSec/zynksec/discussions). For anything sensitive, use [`SECURITY.md`](SECURITY.md).
