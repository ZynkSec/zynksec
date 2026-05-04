# @zynksec/web

Zynksec dashboard — Next.js 15 (App Router) + Tailwind +
shadcn-compatible primitives.

## Phase 4 Sprint 1 scope

Read-only views over the FastAPI backend:

- `/` redirects to `/scans`.
- `/scans` — list of scans for the implicit Local Dev project,
  newest first, with a per-row finding count.
- `/scans/[id]` — single scan with HTTP findings (ZAP) and code
  findings (gitleaks / semgrep / osv-scanner / trivy) tables, both
  filterable by severity via a URL search param.

No auth, no scan triggering, no Target / ScanGroup CRUD this
sprint — those are explicit deferrals (see the PR description).

## Local dev

The frontend runs alongside the rest of the stack via
docker-compose:

```
docker compose --profile dev up -d
# → http://localhost:3000
```

For a host-side run outside compose:

```
cp .env.example .env.local
pnpm install
pnpm --filter @zynksec/web dev
```

## Scripts

- `pnpm --filter @zynksec/web dev` — dev server with HMR.
- `pnpm --filter @zynksec/web build` — production build.
- `pnpm --filter @zynksec/web typecheck` — `tsc --noEmit`.
- `pnpm --filter @zynksec/web test` — Vitest (one smoke test in
  Sprint 1; Playwright comes in a future sprint).

## API client

Hand-typed wire shapes in `lib/api/types.ts`; thin fetch wrapper
in `lib/api/client.ts`. Server components do the data fetching
directly — no SWR / React Query / TanStack Query in Sprint 1
(server components solve the cache concerns those libs address
at this scope).
