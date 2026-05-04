import type { Metadata } from "next";
import type { ReactElement, ReactNode } from "react";

import "@/styles/globals.css";

/**
 * Root layout — shared chrome for every page.
 *
 * Phase 4 Sprint 1: minimal nav (a single "Scans" link to the
 * list view).  Future sprints add Targets, ScanGroups, Settings,
 * etc.  Server component — no client-side nav state needed yet.
 */
export const metadata: Metadata = {
  title: "Zynksec",
  description: "Zynksec security platform — scan results dashboard.",
};

export default function RootLayout({ children }: { children: ReactNode }): ReactElement {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <header className="border-b">
          <nav className="container flex h-14 items-center gap-6">
            <span className="text-lg font-semibold">Zynksec</span>
            <a
              href="/scans"
              className="text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              Scans
            </a>
          </nav>
        </header>
        <main className="container py-6">{children}</main>
      </body>
    </html>
  );
}
