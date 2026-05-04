/**
 * CodeFindingsTable — file-shaped findings (gitleaks / semgrep /
 * osv-scanner / trivy) for the scan detail page.  Columns:
 * Severity, File, Line, Rule, Description.  Description maps to
 * ``redacted_preview`` — operator-facing copy that's already
 * been redacted server-side (gitleaks plaintext secrets are
 * hashed; semgrep/osv/trivy previews are descriptive strings).
 *
 * Line column shows "—" for findings without line context (OSV
 * package-shaped, Trivy DS-0026 absence-of-directive, etc.).
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
import type { CodeFinding } from "@/lib/api/types";
import { severityBadgeVariant } from "@/lib/severity";

export interface CodeFindingsTableProps {
  findings: CodeFinding[];
}

export function CodeFindingsTable({ findings }: CodeFindingsTableProps): ReactElement {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Severity</TableHead>
          <TableHead>File</TableHead>
          <TableHead>Line</TableHead>
          <TableHead>Rule</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.id}>
            <TableCell>
              <Badge variant={severityBadgeVariant(f.severity)}>{f.severity}</Badge>
            </TableCell>
            <TableCell className="max-w-[18rem] truncate font-mono text-xs">
              {f.file_path}
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">{f.line_number ?? "—"}</TableCell>
            <TableCell className="text-xs">
              <span className="font-mono">{f.rule_id}</span>
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">{f.redacted_preview}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
