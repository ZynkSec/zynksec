/**
 * Hand-typed wire shapes for the FastAPI backend's scan endpoints.
 *
 * Phase 4 Sprint 1: deliberately NOT generated from OpenAPI — the
 * surface is small (4 types) and a hand-rolled definition keeps
 * the dependency graph free of openapi-typescript / orval / ...
 * The trade-off is that backend schema changes require a manual
 * edit here; the integration tests in tests/integration/ are the
 * canonical contract, and a wire-shape probe (`curl
 * http://localhost:8000/api/v1/scans | jq`) is the source of
 * truth when these drift.
 *
 * Last verified against:
 *   - apps/api/src/zynksec_api/schemas/scan.py::ScanRead
 *   - apps/api/src/zynksec_api/schemas/code_finding.py::CodeFindingRead
 *   - packages/shared-schema/src/zynksec_schema/finding.py::Finding
 */

export type Severity = "low" | "medium" | "high" | "critical";

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface TargetSummary {
  id: string;
  name: string;
  url: string;
}

/**
 * HTTP-shaped finding (ZAP).  Mirrors the canonical Pydantic
 * Finding from packages/shared-schema/.../finding.py.  Nested
 * structure preserved so taxonomy.cwe / location.url etc. stay
 * accessible without flattening.
 */
export interface Finding {
  id: string;
  fingerprint: string;
  schema_version: number;
  scan_id: string;
  taxonomy: {
    zynksec_id: string;
    cwe: number | null;
    owasp_top10: string | null;
  };
  severity: {
    level: Severity;
    confidence: "low" | "medium" | "high";
  };
  location: {
    url: string;
    method: string | null;
    parameter: string | null;
  };
  evidence: {
    engine: string;
    rule_id: string;
    request: string | null;
    response_excerpt: string | null;
  };
  lifecycle: {
    status: "new" | "open" | "fixed" | "wont_fix";
    first_seen_at: string;
    last_seen_at: string;
  };
}

/**
 * File-shaped finding (gitleaks / semgrep / osv-scanner / trivy).
 * Mirrors apps/api/.../schemas/code_finding.py::CodeFindingRead.
 *
 * line_number is nullable since migration 0009 — OSV-Scanner and
 * some Trivy rules (e.g. DS-0026 "no HEALTHCHECK") have no line
 * context to point at.
 */
export interface CodeFinding {
  id: string;
  scan_id: string;
  file_path: string;
  line_number: number | null;
  column_number: number | null;
  rule_id: string;
  secret_kind: string | null;
  severity: Severity;
  redacted_preview: string;
  commit_sha: string | null;
  created_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  target_url: string;
  target: TargetSummary | null;
  scan_group_id: string | null;
  scan_profile: string;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  failure_reason: string | null;
  created_at: string;
  scanner: string | null;
  findings: Finding[];
  code_findings: CodeFinding[];
  // Populated by GET /api/v1/scans (list); null on detail and POST
  // responses where the populated lists are authoritative.
  findings_count: number | null;
}

/**
 * Canonical error envelope from the FastAPI side (CLAUDE.md §4):
 * { code, message, request_id, details }.  The frontend's
 * ApiError carries the body so callers can branch on `code`
 * (e.g., distinguish `project_not_found` from `unknown_scanner`).
 */
export interface ApiErrorBody {
  code: string;
  message: string;
  request_id: string;
  details?: Record<string, unknown> | null;
}
