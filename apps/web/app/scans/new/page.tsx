import Link from "next/link";
import type { ReactElement } from "react";

import { NewScanForm } from "@/components/new-scan-form";
import { getScannerCatalog, listTargets } from "@/lib/api/client";

/**
 * /scans/new — server component shell for the NewScanForm.
 *
 * Fetches both Target list + ScannerCatalog server-side so the
 * form's initial render has its props populated without a
 * client-side waterfall.  The form itself is a client component
 * (it owns the submit state).  ``Promise.all`` keeps the two
 * GETs parallel.
 *
 * dynamic = "force-dynamic" so a freshly created Target shows
 * up in the picker without a hard refresh — the catalog and
 * targets list are both small and fast to refetch.
 */
export const dynamic = "force-dynamic";

export default async function NewScanPage(): Promise<ReactElement> {
  const [targets, catalog] = await Promise.all([listTargets(), getScannerCatalog()]);

  return (
    <section className="space-y-6">
      <div>
        <Link
          href="/scans"
          className="text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          ← All scans
        </Link>
      </div>
      <header>
        <h1 className="text-2xl font-semibold">New scan</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Pick a target, choose a scanner, submit. The scan runs asynchronously; you&apos;ll be
          redirected to the detail view once it&apos;s queued.
        </p>
      </header>
      <NewScanForm targets={targets} catalog={catalog} />
    </section>
  );
}
