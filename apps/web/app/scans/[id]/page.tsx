import { notFound } from "next/navigation";
import Link from "next/link";
import type { ReactElement } from "react";

import { CodeFindingsTable } from "@/components/code-findings-table";
import { FindingsTable } from "@/components/findings-table";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, getScan } from "@/lib/api/client";
import type { ScanStatus } from "@/lib/api/types";

/**
 * /scans/[id] — single scan with embedded HTTP and code findings.
 * Server component (the severity filter in Commit 4 is a sibling
 * client component; the detail shell stays server-rendered for
 * fast first-paint).
 *
 * Backend contract: GET /api/v1/scans/{id} returns a single scan
 * with findings AND code_findings populated.  Repo-scanner scans
 * carry code_findings only; ZAP scans carry findings only.  Both
 * may be empty (queued / running / failed scans).
 */
export const dynamic = "force-dynamic";

const STATUS_VARIANT: Record<
  ScanStatus,
  "status-queued" | "status-running" | "status-completed" | "status-failed"
> = {
  queued: "status-queued",
  running: "status-running",
  completed: "status-completed",
  failed: "status-failed",
};

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function ScanDetailPage({ params }: PageProps): Promise<ReactElement> {
  const { id } = await params;
  let scan;
  try {
    scan = await getScan(id);
  } catch (err) {
    // 404 from the API surfaces as a Next.js notFound() so the
    // built-in not-found.tsx renders instead of a generic error
    // boundary.  Any other API error bubbles up to error.tsx.
    if (err instanceof ApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

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

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center gap-3">
            <CardTitle className="font-mono text-base">{scan.id}</CardTitle>
            <Badge variant={STATUS_VARIANT[scan.status]}>{scan.status}</Badge>
            <Badge variant="outline">{scan.scan_profile}</Badge>
            {scan.scanner && <Badge variant="outline">{scan.scanner}</Badge>}
          </div>
        </CardHeader>
        <CardContent className="grid gap-4 text-sm md:grid-cols-2">
          <div>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Target</p>
            <p className="mt-1 break-all">{scan.target?.name ?? scan.target_url}</p>
            {scan.target?.url && (
              <p className="text-xs text-muted-foreground break-all">{scan.target.url}</p>
            )}
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Created</p>
            <p className="mt-1">{fmtDate(scan.created_at)}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Started</p>
            <p className="mt-1">{fmtDate(scan.started_at)}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Completed</p>
            <p className="mt-1">{fmtDate(scan.completed_at)}</p>
          </div>
          {scan.failure_reason && (
            <div className="md:col-span-2">
              <p className="text-xs uppercase tracking-wide text-destructive">Failure reason</p>
              <p className="mt-1 break-words text-destructive">{scan.failure_reason}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {scan.findings.length === 0 && scan.code_findings.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-base font-medium">No findings</p>
            <p className="mt-1 text-sm text-muted-foreground">
              {scan.status === "completed"
                ? "The scan completed cleanly — nothing to report."
                : `Findings appear here once the scan finishes (currently ${scan.status}).`}
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {scan.findings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  HTTP findings{" "}
                  <span className="ml-1 text-sm font-normal text-muted-foreground">
                    ({scan.findings.length})
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <FindingsTable findings={scan.findings} />
              </CardContent>
            </Card>
          )}
          {scan.code_findings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  Code findings{" "}
                  <span className="ml-1 text-sm font-normal text-muted-foreground">
                    ({scan.code_findings.length})
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <CodeFindingsTable findings={scan.code_findings} />
              </CardContent>
            </Card>
          )}
        </>
      )}
    </section>
  );
}
