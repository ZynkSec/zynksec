/**
 * ScanListTable — read-only table of scans for the dashboard's
 * /scans page.  Server-component-friendly (no client hooks); the
 * row click is a plain <a> so it works without JavaScript.
 *
 * Phase 4 Sprint 1: the findings count column shows ONLY a single
 * total ("12 findings") — the per-row severity breakdown lives
 * on the detail page since the list endpoint doesn't carry the
 * breakdown (would require an extra COUNT-by-severity query for
 * each scan; deferred to a future sprint when that turns out to
 * be a real product need).
 */
import Link from "next/link";
import type { ReactElement } from "react";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Scan, ScanStatus } from "@/lib/api/types";

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
  // ISO is UTC; render in the viewer's local time so an operator
  // in Madrid sees "14:32" not "12:32 UTC".  Server-rendered, so
  // the locale comes from the runtime, not the browser — fine for
  // a dev dashboard.
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}

function fmtTarget(scan: Scan): string {
  if (scan.target?.name) return scan.target.name;
  return scan.target_url;
}

export interface ScanListTableProps {
  scans: Scan[];
}

export function ScanListTable({ scans }: ScanListTableProps): ReactElement {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Status</TableHead>
          <TableHead>Profile</TableHead>
          <TableHead>Scanner</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Findings</TableHead>
          <TableHead>Created</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => (
          <TableRow key={scan.id} className="cursor-pointer">
            <TableCell>
              <Link href={`/scans/${scan.id}`} className="block">
                <Badge variant={STATUS_VARIANT[scan.status]}>{scan.status}</Badge>
              </Link>
            </TableCell>
            <TableCell>
              <Link href={`/scans/${scan.id}`} className="block text-muted-foreground">
                {scan.scan_profile}
              </Link>
            </TableCell>
            <TableCell>
              <Link href={`/scans/${scan.id}`} className="block">
                {scan.scanner ? (
                  <Badge variant="outline">{scan.scanner}</Badge>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </Link>
            </TableCell>
            <TableCell className="max-w-[24rem] truncate">
              <Link href={`/scans/${scan.id}`} className="block truncate">
                {fmtTarget(scan)}
              </Link>
            </TableCell>
            <TableCell>
              <Link href={`/scans/${scan.id}`} className="block">
                {scan.findings_count ?? 0} findings
              </Link>
            </TableCell>
            <TableCell className="text-muted-foreground">
              <Link href={`/scans/${scan.id}`} className="block">
                {fmtDate(scan.created_at)}
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
