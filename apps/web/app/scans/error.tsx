"use client";

import type { ReactElement } from "react";

/**
 * Error boundary for /scans (and nested routes via the App Router
 * convention).  Renders a readable card without leaking stack
 * traces to the user — CLAUDE.md §6 (don't expose internals);
 * the underlying error still appears in the server console for
 * the operator to triage.
 */
export default function ScansError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}): ReactElement {
  // The digest is Next's hashed reference to the server error;
  // surfacing it lets an operator correlate with the server log
  // without exposing the original exception text.
  return (
    <section className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold">Scans</h1>
      </header>
      <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-6">
        <p className="text-base font-medium text-destructive">Could not load scans</p>
        <p className="mt-1 text-sm text-muted-foreground">
          The dashboard couldn&apos;t reach the API. Check that the API service is up and that{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">NEXT_PUBLIC_API_URL</code> points
          at it.
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
