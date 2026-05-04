/**
 * Smoke test — ScanListTable renders the expected columns and a
 * row's content for each scan.  Phase 4 Sprint 1 has exactly one
 * frontend test: this one.  Its purpose is to prove the test
 * infra works (Vitest + RTL + path aliases + Tailwind classnames
 * survive the render) without committing the sprint to a broader
 * coverage push.
 *
 * Future sprints add more component tests + a Playwright suite;
 * for now, type-check + build + this single render assertion is
 * the bar we agreed to.
 */
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScanListTable } from "@/components/scan-list-table";
import type { Scan } from "@/lib/api/types";

const SCAN_STUB: Scan = {
  id: "11111111-1111-1111-1111-111111111111",
  project_id: "22222222-2222-2222-2222-222222222222",
  target_url: "http://juice-shop:3000/",
  target: {
    id: "33333333-3333-3333-3333-333333333333",
    name: "juice-shop",
    url: "http://juice-shop:3000/",
  },
  scan_group_id: null,
  scan_profile: "PASSIVE",
  status: "completed",
  started_at: "2026-05-03T00:00:00Z",
  completed_at: "2026-05-03T00:01:00Z",
  failure_reason: null,
  created_at: "2026-05-03T00:00:00Z",
  scanner: "zap",
  findings: [],
  code_findings: [],
  findings_count: 12,
};

describe("ScanListTable", () => {
  it("renders the canonical column headers", () => {
    render(<ScanListTable scans={[SCAN_STUB]} />);

    // The six columns the dashboard contract pins.  If a future
    // commit drops or renames a column, this test fails loud.
    for (const header of ["Status", "Profile", "Scanner", "Target", "Findings", "Created"]) {
      expect(screen.getByRole("columnheader", { name: header })).toBeTruthy();
    }
  });

  it("renders status, scanner, target, and findings count for each scan", () => {
    const { container } = render(<ScanListTable scans={[SCAN_STUB]} />);

    // Exactly one body row per scan.
    const bodyRows = container.querySelectorAll("tbody > tr");
    expect(bodyRows).toHaveLength(1);

    const dataRow = bodyRows[0] as HTMLTableRowElement;
    // Status badge text.
    expect(within(dataRow).getByText("completed")).toBeTruthy();
    // Scanner badge text.
    expect(within(dataRow).getByText("zap")).toBeTruthy();
    // Target name (preferred over target_url when both present).
    expect(within(dataRow).getByText("juice-shop")).toBeTruthy();
    // Aggregated findings count column.
    expect(within(dataRow).getByText("12 findings")).toBeTruthy();
  });
});
