/**
 * FindingsTable — HTTP-shaped findings (ZAP) for the scan detail
 * page.  Columns: Severity, URL, Method, Parameter, Rule,
 * Description.  Description is the taxonomy.zynksec_id since
 * Finding doesn't carry a free-text description field — operators
 * recognise the ZYN-DAST-* tokens and the rule_id is one click
 * away if they need details.
 *
 * Severity filter is applied at the server-component level (the
 * detail page passes the already-filtered list); this component
 * is presentation-only so the same filtering logic works for
 * both finding families.
 */
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
import type { Finding } from "@/lib/api/types";
import { severityBadgeVariant } from "@/lib/severity";

export interface FindingsTableProps {
  findings: Finding[];
}

export function FindingsTable({ findings }: FindingsTableProps): ReactElement {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Severity</TableHead>
          <TableHead>URL</TableHead>
          <TableHead>Method</TableHead>
          <TableHead>Parameter</TableHead>
          <TableHead>Rule</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.id}>
            <TableCell>
              <Badge variant={severityBadgeVariant(f.severity.level)}>{f.severity.level}</Badge>
            </TableCell>
            <TableCell className="max-w-[20rem] truncate font-mono text-xs">
              {f.location.url}
            </TableCell>
            <TableCell className="text-xs uppercase text-muted-foreground">
              {f.location.method ?? "—"}
            </TableCell>
            <TableCell className="text-xs">{f.location.parameter ?? "—"}</TableCell>
            <TableCell className="text-xs">
              <span className="font-mono">{f.evidence.rule_id}</span>
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">{f.taxonomy.zynksec_id}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
