import Link from "next/link";
import type { ReactElement } from "react";

/**
 * 404 fallback for /scans/[id] — the API returned scan_not_found
 * (canonical envelope, status 404), or the URL has a malformed UUID.
 */
export default function ScanNotFound(): ReactElement {
  return (
    <section className="space-y-4">
      <div>
        <Link
          href="/scans"
          className="text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          ← All scans
        </Link>
      </div>
      <div className="rounded-lg border bg-card p-8 text-center">
        <p className="text-base font-medium">Scan not found</p>
        <p className="mt-1 text-sm text-muted-foreground">
          The scan id in the URL doesn&apos;t match any scan in this project.
        </p>
      </div>
    </section>
  );
}
