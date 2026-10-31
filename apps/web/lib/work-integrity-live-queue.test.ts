import { describe, expect, it } from "vitest";
import type { CasePage, CaseRow } from "./work-integrity-cases";
import {
  LIVE_EVIDENCE_REQUIREMENTS, parseLiveIntegrityFilters,
  casePageSnapshot, buildLiveIntegrityPage, liveIntegrityCsv,
} from "./work-integrity-live-queue";

const at = "2026-10-31T10:00:00.000Z";
const row = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 2, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const urgent = row("urgent", { severity: "critical" });
const reviewed = row("reviewed", {
  state: "ACKNOWLEDGED", reviewEventId: "event-1",
  reviewedAt: at, reviewedRevision: 2,
  reviewRationale: "Reviewed and documented",
});
const stale = row("stale", {
  state: "STALE", reviewEventId: "event-2",
  reviewedAt: at, reviewedRevision: 1,
  reviewRationale: "Earlier assessment",
});
const incomplete = row("incomplete", { completeCoverage: false });
const page = (cases: CaseRow[] = [urgent, reviewed, stale, incomplete],
  nextCursor: string | null = null, historyComplete = true,
  cursor: string | null = null): CasePage => ({
  generatedAt: at,
  filters: {
    state: "ALL", severity: "ALL", search: "",
    limit: 25, cursor, includeInfo: true, includeHistorical: false,
  },
  totalWorkItemsExamined: cases.length,
  cases,
  summary: {
    totalOnPage: cases.length, unreviewed: 0, investigating: 0,
    acknowledged: 0, dismissed: 0, reopened: 0, stale: 0,
    noLongerDetected: 0, critical: 0, attention: 0,
    informational: 0, partialCoverage: 0, reviewed: 0, historicalOnly: 0,
  },
  nextCursor, reviewEventsFetched: 2, historyComplete,
  limitations: ["Bounded work-item page"],
});
describe("live analyst queue input", () => {
  it("uses bounded defaults", () => {
    expect(parseLiveIntegrityFilters({})).toEqual({
      priority: "ALL", reviewed: "ALL", offset: 0, pageSize: 25,
    });
  });
  it("accepts priority filter", () => {
    expect(parseLiveIntegrityFilters({ priority: "P0" }).priority).toBe("P0");
  });
  it("accepts review filter", () => {
    expect(parseLiveIntegrityFilters({ reviewed: "NO" }).reviewed).toBe("NO");
  });
  it("accepts explicit pagination", () => {
    expect(parseLiveIntegrityFilters({ offset: "10", pageSize: "5" }).offset).toBe(10);
  });
  it("rejects unknown priority", () => {
    expect(() => parseLiveIntegrityFilters({ priority: "P9" })).toThrow();
  });
  it("rejects unknown review state", () => {
    expect(() => parseLiveIntegrityFilters({ reviewed: "MAYBE" })).toThrow();
  });
  it("rejects negative offset", () => {
    expect(() => parseLiveIntegrityFilters({ offset: "-1" })).toThrow();
  });
  it("rejects fractional offset", () => {
    expect(() => parseLiveIntegrityFilters({ offset: "1.5" })).toThrow();
  });
  it("rejects leading zeros", () => {
    expect(() => parseLiveIntegrityFilters({ offset: "01" })).toThrow();
  });
  it("rejects nonnumeric page size", () => {
    expect(() => parseLiveIntegrityFilters({ pageSize: "all" })).toThrow();
  });
  it("rejects zero page size", () => {
    expect(() => parseLiveIntegrityFilters({ pageSize: "0" })).toThrow();
  });
  it("rejects page size over limit", () => {
    expect(() => parseLiveIntegrityFilters({ pageSize: "101" })).toThrow();
  });
  it("rejects excessive offset", () => {
    expect(() => parseLiveIntegrityFilters({ offset: "100001" })).toThrow();
  });
});
describe("live case snapshot conversion", () => {
  it("preserves tenant", () => {
    expect(casePageSnapshot("org-a", page()).organizationId).toBe("org-a");
  });
  it("preserves capture time", () => {
    expect(casePageSnapshot("org-a", page()).capturedAt).toBe(at);
  });
  it("marks incomplete linked records partial", () => {
    expect(casePageSnapshot("org-a", page()).complete).toBe(false);
  });
  it("marks continuing cursor partial", () => {
    expect(casePageSnapshot("org-a", page([urgent], "next")).complete).toBe(false);
  });
  it("marks previous cursor partial", () => {
    expect(casePageSnapshot("org-a", page([urgent], null, true, "previous")).complete).toBe(false);
  });
  it("marks truncated audit history partial", () => {
    expect(casePageSnapshot("org-a", page([urgent], null, false)).complete).toBe(false);
  });
  it("marks fully bounded first page complete", () => {
    expect(casePageSnapshot("org-a", page([urgent])).complete).toBe(true);
  });
  it("rejects invalid organization", () => {
    expect(() => casePageSnapshot("", page())).toThrow();
  });
  it("rejects duplicate case identities", () => {
    expect(() => casePageSnapshot("org-a", page([urgent, urgent]))).toThrow();
  });
  it("rejects malformed case revision", () => {
    expect(() => casePageSnapshot("org-a",
      page([{ ...urgent, taskRevision: 0 }]))).toThrow();
  });
});
describe("integrated live analyst report", () => {
  const report = buildLiveIntegrityPage("org-a", page());
  it("reports live tenant", () => expect(report.organizationId).toBe("org-a"));
  it("counts current page cases", () => expect(report.totalCasesOnWorkPage).toBe(4));
  it("counts priority P0", () => expect(report.priorities.P0).toBe(2));
  it("reports evidence blockers", () => expect(report.evidence.blocked).toBeGreaterThan(0));
  it("reports missing review", () => expect(report.evidence.missingReview).toBe(2));
  it("reports stale review", () => expect(report.evidence.staleReview).toBe(1));
  it("reports incomplete coverage", () => expect(report.metrics.incompleteCoverage).toBe(1));
  it("reports diagnostic grouping", () => expect(report.groups[0]?.count).toBe(4));
  it("generates review batches", () => expect(report.batches.length).toBeGreaterThan(0));
  it("preserves source limitations", () => {
    expect(report.limitations).toContain("Bounded work-item page");
  });
  it("does not claim security verification", () => {
    expect(report.limitations.some(x => x.includes("security verification"))).toBe(true);
  });
  it("filters P0 cases", () => {
    const filtered = buildLiveIntegrityPage("org-a", page(), { priority: "P0" });
    expect(filtered.entries).toHaveLength(2);
  });
  it("filters reviewed cases", () => {
    const filtered = buildLiveIntegrityPage("org-a", page(), { reviewed: "YES" });
    expect(filtered.entries).toHaveLength(2);
  });
  it("filters unreviewed cases", () => {
    const filtered = buildLiveIntegrityPage("org-a", page(), { reviewed: "NO" });
    expect(filtered.entries).toHaveLength(2);
  });
  it("supports offset pagination", () => {
    const first = buildLiveIntegrityPage("org-a", page(), { pageSize: "2" });
    const second = buildLiveIntegrityPage("org-a", page(), {
      pageSize: "2", offset: "2",
    });
    expect(first.nextOffset).toBe(2);
    expect(second.nextOffset).toBeNull();
    expect(new Set([...first.entries, ...second.entries].map(x => x.caseKey)).size).toBe(4);
  });
  it("returns empty page beyond end", () => {
    expect(buildLiveIntegrityPage("org-a", page(), {
      offset: "100",
    }).entries).toEqual([]);
  });
  it("preserves work-item continuation", () => {
    expect(buildLiveIntegrityPage("org-a", page([urgent], "next")).nextWorkCursor).toBe("next");
  });
  it("reports missing evidence fields per case", () => {
    const item = report.entries.find(x => x.workItemId === "urgent");
    expect(item?.missingEvidence).toContain("reviewEventId");
  });
  it("reports stale revision evidence gap", () => {
    const item = report.entries.find(x => x.workItemId === "stale");
    expect(item?.missingEvidence).toContain("revision");
  });
  it("reports ready evidence on fully covered reviewed case", () => {
    const ready = buildLiveIntegrityPage("org-a", page([reviewed]));
    expect(ready.entries[0]?.evidenceReady).toBe(true);
  });
  it("reports no evidence ready under incomplete source", () => {
    const partial = buildLiveIntegrityPage("org-a", page([reviewed], "next"));
    expect(partial.entries[0]?.evidenceReady).toBe(false);
  });
  it("exports CSV", () => expect(liveIntegrityCsv(report)).toContain("\r\n"));
  it("exports only filtered cases", () => {
    const filtered = buildLiveIntegrityPage("org-a", page(), { priority: "P0" });
    expect(liveIntegrityCsv(filtered).split("\r\n")).toHaveLength(4);
  });
  it("neutralizes spreadsheet formulas", () => {
    const injected = row("=HYPERLINK");
    expect(liveIntegrityCsv(buildLiveIntegrityPage("org-a", page([injected]))))
      .toContain("'=HYPERLINK");
  });
  it("keeps evidence policy explicit", () => {
    expect(LIVE_EVIDENCE_REQUIREMENTS[0]?.requireHumanReview).toBe(true);
  });
});

describe("live queue isolation and edge-case guarantees", () => {
  it("preserves organization identity across filtered reports", () => {
    for (const priority of ["P0", "P1", "P2", "P3", "P4"] as const) {
      const report = buildLiveIntegrityPage("tenant-private", page(), { priority });
      expect(report.organizationId).toBe("tenant-private");
    }
  });
  it("never reports complete capture when any linked case is partial", () => {
    for (const entry of [urgent, reviewed, stale, incomplete]) {
      const result = buildLiveIntegrityPage("org-a", page([entry]));
      expect(result.snapshotComplete).toBe(entry.completeCoverage);
    }
  });
  it("does not silently drop the source page cursor", () => {
    const result = buildLiveIntegrityPage("org-a", page([urgent], "opaque-next"));
    expect(result.nextWorkCursor).toBe("opaque-next");
    expect(result.snapshotComplete).toBe(false);
  });
  it("distinguishes pagination of cases from work-item pagination", () => {
    const result = buildLiveIntegrityPage("org-a",
      page([urgent, reviewed], "opaque-next"), { pageSize: "1" });
    expect(result.nextOffset).toBe(1);
    expect(result.nextWorkCursor).toBe("opaque-next");
  });
  it("does not declare a previous cursor page complete", () => {
    const result = buildLiveIntegrityPage("org-a",
      page([reviewed], null, true, "opaque-previous"));
    expect(result.snapshotComplete).toBe(false);
    expect(result.entries[0]?.evidenceReady).toBe(false);
  });
  it("does not count reviewed cases as missing review", () => {
    const result = buildLiveIntegrityPage("org-a", page([reviewed]));
    expect(result.evidence.missingReview).toBe(0);
  });
  it("treats a stale review as evidence blocked", () => {
    const result = buildLiveIntegrityPage("org-a", page([stale]));
    expect(result.evidence.blocked).toBe(1);
    expect(result.entries[0]?.missingEvidence).toContain("revision");
  });
  it("does not treat historical-only cases as current findings", () => {
    const historical = row("old", {
      state: "NO_LONGER_DETECTED", historicalOnly: true,
      severity: null, diagnostic: null, recommendation: null,
    });
    const result = buildLiveIntegrityPage("org-a", page([historical]));
    expect(result.metrics.historical).toBe(1);
    expect(result.entries[0]?.state).toBe("NO_LONGER_DETECTED");
  });
  it("supports an empty page without fabricating cases", () => {
    const result = buildLiveIntegrityPage("org-a", page([]));
    expect(result.entries).toEqual([]);
    expect(result.totalCasesOnWorkPage).toBe(0);
    expect(result.evidence.total).toBe(0);
  });
  it("keeps all priority buckets present when empty", () => {
    const result = buildLiveIntegrityPage("org-a", page([]));
    expect(Object.keys(result.priorities).sort()).toEqual(["P0", "P1", "P2", "P3", "P4"]);
  });
  it("returns stable deterministic order", () => {
    const original = buildLiveIntegrityPage("org-a", page([reviewed, urgent, stale]));
    const reordered = buildLiveIntegrityPage("org-a", page([stale, reviewed, urgent]));
    expect(original.entries.map(item => item.caseKey)).toEqual(
      reordered.entries.map(item => item.caseKey));
  });
  it("does not mutate source cases during report generation", () => {
    const cases = [urgent, reviewed, stale].map(item => ({ ...item }));
    const original = JSON.stringify(cases);
    buildLiveIntegrityPage("org-a", page(cases));
    expect(JSON.stringify(cases)).toBe(original);
  });
  it("does not leak another tenant ID into report identity", () => {
    const a = buildLiveIntegrityPage("tenant-a", page([urgent]));
    const b = buildLiveIntegrityPage("tenant-b", page([urgent]));
    expect(a.organizationId).toBe("tenant-a");
    expect(b.organizationId).toBe("tenant-b");
  });
  it("keeps filtered pagination counts local to selected work page", () => {
    const result = buildLiveIntegrityPage("org-a", page([urgent, reviewed]),
      { reviewed: "NO", offset: "1" });
    expect(result.totalMatching).toBe(1);
    expect(result.entries).toHaveLength(0);
    expect(result.nextOffset).toBeNull();
  });
  it("exports no case rows for empty selection", () => {
    const result = buildLiveIntegrityPage("org-a", page([urgent]),
      { reviewed: "YES" });
    expect(liveIntegrityCsv(result).trim().split("\r\n")).toHaveLength(1);
  });
  it("does not expose a false claim of organization-wide coverage", () => {
    const result = buildLiveIntegrityPage("org-a", page([urgent]));
    expect(result.limitations.some(line =>
      line.includes("bounded work-item cursor page"))).toBe(true);
  });
  it("handles large but bounded offsets without throwing", () => {
    const result = buildLiveIntegrityPage("org-a", page([urgent]),
      { offset: "100000" });
    expect(result.entries).toEqual([]);
  });
  it("rejects exponential notation in pagination", () => {
    expect(() => parseLiveIntegrityFilters({ offset: "1e2" })).toThrow();
  });
  it("rejects leading plus in pagination", () => {
    expect(() => parseLiveIntegrityFilters({ pageSize: "+10" })).toThrow();
  });
  it("rejects whitespace in pagination", () => {
    expect(() => parseLiveIntegrityFilters({ offset: " 2 " })).toThrow();
  });
});
