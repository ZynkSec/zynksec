import type { ReactElement } from "react";

import { ScanListTable } from "@/components/scan-list-table";
import { listScans } from "@/lib/api/client";

/**
 * /scans — read-only list view of every scan in the implicit
 * Local Dev project, newest first.  Server component: fetches
 * directly via lib/api/client at request time (no client-side
 * effects, no SWR).  Errors are caught by the sibling error.tsx
 * boundary; an empty result shows an inline empty state.
 *
 * Disable static optimisation — scan state changes frequently
 * (queued → running → completed minutes apart) and a cached page
 * would lie about the running set.
 */
export const dynamic = "force-dynamic";

export default async function ScansPage(): Promise<ReactElement> {
  const scans = await listScans();

  if (scans.length === 0) {
    return (
      <section className="space-y-4">
        <header>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="text-sm text-muted-foreground">
            Read-only view of scans in the Local Dev project.
          </p>
        </header>
        <div className="rounded-lg border bg-card p-8 text-center">
          <p className="text-base font-medium">No scans yet</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Scans are created via the API in this sprint —{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/scans</code>. The
            dashboard will pick them up automatically.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="space-y-4">
      <header className="flex items-baseline justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="text-sm text-muted-foreground">
            {scans.length} scan{scans.length === 1 ? "" : "s"} in Local Dev, newest first.
          </p>
        </div>
      </header>
      <div className="rounded-lg border">
        <ScanListTable scans={scans} />
      </div>
    </section>
  );
}
