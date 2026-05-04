/**
 * Thin TypeScript wrapper over the FastAPI endpoints the dashboard
 * consumes.
 *
 * Phase 4 Sprint 1 surface (server components):
 *   - listScans() → GET /api/v1/scans (newest first)
 *   - getScan(id) → GET /api/v1/scans/{id} (with embedded findings)
 *
 * Phase 4 Sprint 2 surface (server + client components):
 *   - listTargets()         → GET /api/v1/targets  (server)
 *   - getScannerCatalog()   → GET /api/v1/scanners (server)
 *   - createScan(body)      → POST /api/v1/scans   (client)
 *
 * Deliberately NOT using SWR / React Query / TanStack.  The form
 * is a single submit + redirect, no client-side cache to share;
 * useState + native fetch is the right shape at this scope.  If
 * a future sprint adds 10 forms or real-time updates, revisit.
 *
 * Cache strategy: ``cache: "no-store"`` on every server-side GET
 * so the dashboard always sees the latest scan state.  ZAP scans
 * take minutes to complete; an aggressively cached list view
 * would lie about which scans are still running.
 */

import type {
  ApiErrorBody,
  Scan,
  ScanCreateRequest,
  ScannerCatalog,
  Target,
} from "@/lib/api/types";

/**
 * Resolve the API base URL from the environment.
 *
 * Phase 4 Sprint 1's data-fetching helpers run ONLY inside server
 * components — the dashboard's client components don't call the
 * API directly.  That means we can prefer a server-only env var
 * (``INTERNAL_API_URL``) so the server-side fetch reaches the
 * API service over Docker's intra-network DNS (``http://api:8000``)
 * while the browser bundle never sees that hostname.
 *
 * Resolution order:
 *   1. ``INTERNAL_API_URL`` — set by the docker-compose frontend
 *      service to ``http://api:8000`` so server-component fetches
 *      bypass the host port.
 *   2. ``NEXT_PUBLIC_API_URL`` — the browser-visible fallback;
 *      also the only var available if a future sprint adds a
 *      client-side API call.
 *   3. ``http://localhost:8000`` — local-dev default for a
 *      host-side ``pnpm dev`` outside compose.
 *
 * If both 1 and 2 are set, the server uses (1) and any future
 * client-component fetch would use (2); both pointing at the same
 * logical API is the operator's job to keep consistent.
 */
const API_BASE =
  process.env.INTERNAL_API_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/**
 * Thrown when the backend returns a non-2xx response.  Carries
 * the canonical envelope when the response body is JSON-shaped;
 * falls back to a synthetic envelope for transport-level errors
 * (network unreachable, HTML error page, etc.) so callers always
 * get the same shape.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody) {
    super(`${body.code}: ${body.message}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

async function readJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let body: ApiErrorBody;
    try {
      body = (await res.json()) as ApiErrorBody;
    } catch {
      // Non-JSON error response (HTML error page, empty body).
      // Synthesise an envelope so the caller's branching code
      // doesn't need to handle two error shapes.
      body = {
        code: "transport_error",
        message: `HTTP ${res.status} ${res.statusText}`,
        request_id: "",
      };
    }
    throw new ApiError(res.status, body);
  }
  return (await res.json()) as T;
}

/**
 * GET /api/v1/scans — newest-first list of scans for the implicit
 * Local Dev project.
 *
 * Each row carries findings=[] / code_findings=[]; the populated
 * lists live on the detail endpoint (drill-in via getScan).
 * findings_count is an aggregate total the UI can render directly.
 */
export async function listScans(): Promise<Scan[]> {
  const res = await fetch(`${API_BASE}/api/v1/scans`, { cache: "no-store" });
  return readJson<Scan[]>(res);
}

/**
 * GET /api/v1/scans/{id} — single scan with embedded findings.
 */
export async function getScan(id: string): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(id)}`, {
    cache: "no-store",
  });
  return readJson<Scan>(res);
}

/**
 * GET /api/v1/targets — every Target in the implicit Local Dev
 * project.  Powers the existing-target picker on the New Scan
 * form.
 */
export async function listTargets(): Promise<Target[]> {
  const res = await fetch(`${API_BASE}/api/v1/targets`, { cache: "no-store" });
  return readJson<Target[]>(res);
}

/**
 * GET /api/v1/scanners — per-kind plugin catalogue.  Pure
 * metadata: cached for the request only (still ``no-store`` so a
 * mid-session plugin addition surfaces immediately).
 */
export async function getScannerCatalog(): Promise<ScannerCatalog> {
  const res = await fetch(`${API_BASE}/api/v1/scanners`, { cache: "no-store" });
  return readJson<ScannerCatalog>(res);
}

/**
 * POST /api/v1/scans — enqueue a new scan.  Returns the freshly
 * persisted Scan with status="queued" and empty findings; the
 * caller redirects to /scans/{response.id} where the detail page
 * picks up the running state.
 *
 * The XOR between target_id and target_url is enforced server-
 * side (canonical-envelope 422 ``scan_target_spec_conflict`` for
 * both/neither).  Callers should pre-validate but the API is the
 * source of truth.
 */
export async function createScan(body: ScanCreateRequest): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/v1/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  return readJson<Scan>(res);
}
