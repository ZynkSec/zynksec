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

/** TargetKind — mirrors zynksec_scanners.types.TargetKind. */
export type TargetKind = "web_app" | "api" | "repo";

/** ScanProfile — mirrors zynksec_schema.scan_profile.ScanProfile. */
export type ScanProfile = "PASSIVE" | "SAFE_ACTIVE" | "AGGRESSIVE";

export interface TargetSummary {
  id: string;
  name: string;
  url: string;
}

/**
 * Full Target record returned by GET /api/v1/targets.  Mirrors
 * apps/api/.../schemas/target.py::TargetRead.  Used by the
 * "New Scan" form's existing-target picker.
 */
export interface Target {
  id: string;
  project_id: string;
  name: string;
  url: string;
  kind: TargetKind;
  created_at: string;
  updated_at: string;
}

/**
 * Per-kind catalogue entry from GET /api/v1/scanners.  Drives the
 * dashboard's kind-aware scanner + scan-profile pickers.
 */
export interface ScannerEntry {
  name: string;
  is_default: boolean;
}

export interface KindCatalog {
  scanners: ScannerEntry[];
  scan_profiles: ScanProfile[];
}

export interface ScannerCatalog {
  kinds: Record<TargetKind, KindCatalog>;
}

/**
 * Body of POST /api/v1/scans.  Mirrors
 * apps/api/.../schemas/scan.py::ScanCreate.  Exactly one of
 * target_id or target_url must be provided; the API returns a
 * canonical-envelope 422 (scan_target_spec_conflict) for
 * both/neither.  scan_profile + scanner are optional (the API
 * resolves defaults from the target's kind).
 */
export interface ScanCreateRequest {
  target_id?: string;
  target_url?: string;
  scan_profile?: ScanProfile;
  scanner?: string;
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
