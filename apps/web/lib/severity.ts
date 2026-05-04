/**
 * Severity helpers — Phase 4 Sprint 1.
 *
 * The 4-level enum (low / medium / high / critical) is shared by
 * both finding tables (HTTP-shaped Findings + file-shaped
 * CodeFindings).  These helpers keep the rendering decisions in
 * one place so future scanner additions don't touch every UI
 * component.
 */

import type { Severity } from "@/lib/api/types";

export const ALL_SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"] as const;

/**
 * Stable order for the per-row "2H 1M 0L" finding-count summary
 * — most-severe first matches operator scanning behaviour.
 */
export const SEVERITY_ORDER: readonly Severity[] = ALL_SEVERITIES;

/**
 * Compact letter for the per-row summary column (C/H/M/L).
 * Used as the rightmost segment of "2C 5H 1M 0L".
 */
export function severityLetter(severity: Severity): "C" | "H" | "M" | "L" {
  switch (severity) {
    case "critical":
      return "C";
    case "high":
      return "H";
    case "medium":
      return "M";
    case "low":
      return "L";
  }
}

/**
 * Map a severity to the corresponding Badge variant key.  Kept
 * here rather than inline so the badge.tsx variant catalogue stays
 * the single source of truth — call sites just pass the result of
 * this function as the variant prop.
 */
export function severityBadgeVariant(
  severity: Severity,
): "severity-low" | "severity-medium" | "severity-high" | "severity-critical" {
  return `severity-${severity}` as const;
}

/**
 * Parse the ?severity= URL search param into a Set of canonical
 * severity values.  Garbage / unknown tokens are silently ignored
 * so a malformed link doesn't 422 — operators get the broadest
 * reasonable interpretation of their URL.
 *
 * Empty / missing param → no filter (caller should treat this as
 * "show all").  Caller decides the all-vs-empty distinction; this
 * function never returns the full set as a substitute for "no
 * filter".
 */
export function parseSeverityParam(raw: string | string[] | undefined): Set<Severity> {
  if (!raw) return new Set();
  const values = Array.isArray(raw) ? raw : raw.split(",");
  const out = new Set<Severity>();
  for (const v of values) {
    const trimmed = v.trim().toLowerCase();
    if ((ALL_SEVERITIES as readonly string[]).includes(trimmed)) {
      out.add(trimmed as Severity);
    }
  }
  return out;
}

/**
 * Apply a parsed severity filter to a list of findings (HTTP or
 * code).  An empty filter set means "no filter" → return the
 * input unchanged; this is the convention the parser pairs with.
 */
export function filterBySeverity<T extends { severity: Severity | { level: Severity } }>(
  findings: readonly T[],
  filter: ReadonlySet<Severity>,
): T[] {
  if (filter.size === 0) return [...findings];
  return findings.filter((f) => {
    const sev = typeof f.severity === "string" ? f.severity : f.severity.level;
    return filter.has(sev);
  });
}
