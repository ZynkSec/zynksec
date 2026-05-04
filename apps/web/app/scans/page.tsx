import type { ReactElement } from "react";

/**
 * Placeholder shell for /scans — populated by Commit 2 (scan
 * list page).  Lands here so the Next.js build at the Commit 1
 * boundary doesn't 404 on the route the layout's nav links to.
 */
export default function ScansPage(): ReactElement {
  return (
    <section>
      <h1 className="text-2xl font-semibold">Scans</h1>
      <p className="mt-2 text-sm text-muted-foreground">Scan list view lands in the next commit.</p>
    </section>
  );
}
