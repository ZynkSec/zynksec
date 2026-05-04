"use client";

import Link from "next/link";
import type { ReactElement } from "react";

/**
 * Error boundary for /scans/new.  If the targets / catalog fetch
 * fails (API unreachable, 5xx) this renders an inline card
 * without exposing the underlying exception text — same pattern
 * as /scans/error.tsx (CLAUDE.md §6).
 */
export default function NewScanError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}): ReactElement {
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
      <header>
        <h1 className="text-2xl font-semibold">New scan</h1>
      </header>
      <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-6">
        <p className="text-base font-medium text-destructive">Could not load form data</p>
        <p className="mt-1 text-sm text-muted-foreground">
          The dashboard couldn&apos;t fetch the target list or scanner catalog. Check that the API
          service is up.
        </p>
        {error.digest && (
          <p className="mt-2 text-xs text-muted-foreground">Reference: {error.digest}</p>
        )}
        <button
          type="button"
          onClick={reset}
          className="mt-4 inline-flex h-9 items-center rounded-md border bg-background px-3 text-sm font-medium hover:bg-accent"
        >
          Retry
        </button>
      </div>
    </section>
  );
}
