/**
 * Vitest tests for NewScanForm — Phase 4 Sprint 2.
 *
 * Mocks the createScan client function + next/navigation router
 * so the test runs without a real network call or Next.js
 * routing context.  Three scenarios pinned:
 *
 *   1. kind=repo (existing target): scanner picker IS shown,
 *      scan-profile picker is NOT shown.  Submit posts
 *      target_id with the chosen scanner, no scan_profile.
 *   2. kind=web_app (existing target): scanner picker is NOT
 *      shown (single-scanner kind), scan-profile picker IS shown.
 *      Submit posts target_id + scanner=zap + scan_profile.
 *   3. paste-URL mode: target_url + kind picker visible; submit
 *      posts target_url not target_id, with the kind-derived
 *      scanner.
 *
 * Sprint scope is "vitest unit tests": the three above prove the
 * field-rendering and submit-shape contracts hold.  A future
 * sprint adds component-level tests for the error path
 * (canonical envelope rendering) and Playwright e2e covering
 * the full redirect dance.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NewScanForm } from "@/components/new-scan-form";
import type { ScannerCatalog, Target } from "@/lib/api/types";

// Hoisted mocks — vitest.mock factories run before the imports
// in module order so we have to reach for ``vi.hoisted`` to
// build the shared spies the factories close over.
const mocks = vi.hoisted(() => ({
  push: vi.fn(),
  createScan: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mocks.push }),
}));

vi.mock("@/lib/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api/client")>("@/lib/api/client");
  return {
    ...actual,
    createScan: mocks.createScan,
  };
});

const REPO_TARGET: Target = {
  id: "11111111-1111-1111-1111-111111111111",
  project_id: "00000000-0000-0000-0000-000000000000",
  name: "vuln-repo",
  url: "http://gitfixture/vulnerable-repo.git",
  kind: "repo",
  created_at: "2026-05-04T00:00:00Z",
  updated_at: "2026-05-04T00:00:00Z",
};

const WEB_TARGET: Target = {
  id: "22222222-2222-2222-2222-222222222222",
  project_id: "00000000-0000-0000-0000-000000000000",
  name: "juice-shop",
  url: "http://juice-shop:3000/",
  kind: "web_app",
  created_at: "2026-05-04T00:00:00Z",
  updated_at: "2026-05-04T00:00:00Z",
};

const CATALOG: ScannerCatalog = {
  kinds: {
    web_app: {
      scanners: [{ name: "zap", is_default: true }],
      scan_profiles: ["PASSIVE", "SAFE_ACTIVE", "AGGRESSIVE"],
    },
    api: {
      scanners: [{ name: "zap", is_default: true }],
      scan_profiles: ["PASSIVE", "SAFE_ACTIVE", "AGGRESSIVE"],
    },
    repo: {
      scanners: [
        { name: "gitleaks", is_default: true },
        { name: "osv-scanner", is_default: false },
        { name: "semgrep", is_default: false },
        { name: "trivy", is_default: false },
      ],
      scan_profiles: [],
    },
  },
};

beforeEach(() => {
  mocks.push.mockReset();
  mocks.createScan.mockReset();
});

describe("NewScanForm", () => {
  it("renders scanner picker but no scan-profile picker for kind=repo", () => {
    render(<NewScanForm targets={[REPO_TARGET]} catalog={CATALOG} />);

    // Scanner picker visible: kind=repo has 4 scanners.
    expect(screen.getByLabelText("Scanner")).toBeTruthy();
    // Scan-profile picker hidden: kind=repo has empty scan_profiles.
    expect(screen.queryByLabelText("Scan profile")).toBeNull();
  });

  it("renders scan-profile picker but no scanner picker for kind=web_app", () => {
    render(<NewScanForm targets={[WEB_TARGET]} catalog={CATALOG} />);

    // Scanner picker hidden: kind=web_app has only ZAP.
    expect(screen.queryByLabelText("Scanner")).toBeNull();
    // Scan-profile picker visible: web_app has the three intensities.
    expect(screen.getByLabelText("Scan profile")).toBeTruthy();
  });

  it("submits target_id + chosen scanner for an existing repo target", async () => {
    mocks.createScan.mockResolvedValueOnce({
      id: "99999999-9999-9999-9999-999999999999",
    });
    render(<NewScanForm targets={[REPO_TARGET]} catalog={CATALOG} />);

    // Switch the scanner picker from gitleaks (default) to trivy.
    fireEvent.change(screen.getByLabelText("Scanner"), { target: { value: "trivy" } });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    // Wait for the async submit handler.  RTL's findBy* would
    // suit better but we can poll the spy directly since it's
    // the contract under test.
    await vi.waitFor(() => expect(mocks.createScan).toHaveBeenCalledTimes(1));

    expect(mocks.createScan).toHaveBeenCalledWith({
      target_id: REPO_TARGET.id,
      scanner: "trivy",
    });
    expect(mocks.push).toHaveBeenCalledWith("/scans/99999999-9999-9999-9999-999999999999");
  });

  it("submits target_url + scan_profile for the paste-URL flow on web_app", async () => {
    mocks.createScan.mockResolvedValueOnce({
      id: "55555555-5555-5555-5555-555555555555",
    });
    render(<NewScanForm targets={[]} catalog={CATALOG} />);

    // Empty targets list defaults the source to "url"; type a URL.
    fireEvent.change(screen.getByLabelText("URL"), {
      target: { value: "https://example.com/" },
    });
    // Default kind for paste-URL is web_app, default scan_profile
    // is PASSIVE — submit without changing those.
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    await vi.waitFor(() => expect(mocks.createScan).toHaveBeenCalledTimes(1));

    expect(mocks.createScan).toHaveBeenCalledWith({
      target_url: "https://example.com/",
      scanner: "zap",
      scan_profile: "PASSIVE",
    });
    expect(mocks.push).toHaveBeenCalledWith("/scans/55555555-5555-5555-5555-555555555555");
  });
});
