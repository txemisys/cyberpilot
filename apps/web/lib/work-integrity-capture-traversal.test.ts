import { describe, expect, it, vi } from "vitest";
import type { CasePage, CaseRow, CaseScope } from "./work-integrity-cases";
import {
  DEFAULT_CAPTURE_TRAVERSAL, parseCaptureTraversalOptions,
  traverseIntegrityCapture,
} from "./work-integrity-capture-traversal";
import { compareIntegrityCaptures } from "./work-integrity-live-comparison";

const scope: CaseScope = {
  organizationId: "org-a", userId: "user-a", role: "OWNER",
};
const time = "2026-10-31T10:00:00.000Z";
const row = (id: string): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 1,
  severity: "critical", diagnostic: "Missing completion",
  recommendation: "Investigate", state: "UNREVIEWED",
  reviewEventId: null, reviewedAt: null, reviewedRevision: null,
  reviewerUserId: null, reviewRationale: null, reviewReference: null,
  completeCoverage: true, historicalOnly: false,
});
const page = (
  ids: string[], nextCursor: string | null = null,
  overrides: Partial<CasePage> = {},
): CasePage => ({
  generatedAt: time,
  filters: {
    state: "ALL", severity: "ALL", search: "", limit: 50,
    cursor: null, includeInfo: true, includeHistorical: true,
  },
  totalWorkItemsExamined: ids.length,
  cases: ids.map(row),
  summary: {
    totalOnPage: ids.length, unreviewed: ids.length,
    investigating: 0, acknowledged: 0, dismissed: 0,
    reopened: 0, stale: 0, noLongerDetected: 0,
    critical: ids.length, attention: 0, informational: 0,
    partialCoverage: 0, reviewed: 0, historicalOnly: 0,
  },
  nextCursor, reviewEventsFetched: 0,
  historyComplete: true, limitations: [],
  ...overrides,
});
const loader = (...pages: CasePage[]) => {
  const mock = vi.fn();
  for (const result of pages) mock.mockResolvedValueOnce(result);
  return mock;
};
describe("capture traversal input validation", () => {
  it("uses a bounded default policy", () => {
    expect(parseCaptureTraversalOptions({})).toEqual(DEFAULT_CAPTURE_TRAVERSAL);
  });
  it("accepts ten pages", () => {
    expect(parseCaptureTraversalOptions({ maxPages: "10" }).maxPages).toBe(10);
  });
  it("accepts single page", () => {
    expect(parseCaptureTraversalOptions({ maxPages: "1" }).maxPages).toBe(1);
  });
  it("accepts 100 work items per page", () => {
    expect(parseCaptureTraversalOptions({ pageSize: "100" }).pageSize).toBe(100);
  });
  it("accepts 10 work items per page", () => {
    expect(parseCaptureTraversalOptions({ pageSize: "10" }).pageSize).toBe(10);
  });
  it("accepts excluded historical records explicitly", () => {
    expect(parseCaptureTraversalOptions({ includeHistorical: "false" })
      .includeHistorical).toBe(false);
  });
  it("rejects unknown options", () => {
    expect(() => parseCaptureTraversalOptions({ tenantId: "other" })).toThrow();
  });
  it("rejects negative page count", () => {
    expect(() => parseCaptureTraversalOptions({ maxPages: "-1" })).toThrow();
  });
  it("rejects zero page count", () => {
    expect(() => parseCaptureTraversalOptions({ maxPages: "0" })).toThrow();
  });
  it("rejects eleven pages", () => {
    expect(() => parseCaptureTraversalOptions({ maxPages: "11" })).toThrow();
  });
  it("rejects nonstandard page size", () => {
    expect(() => parseCaptureTraversalOptions({ pageSize: "33" })).toThrow();
  });
  it("rejects nonnumeric page count", () => {
    expect(() => parseCaptureTraversalOptions({ maxPages: "many" })).toThrow();
  });
  it("rejects decimal page count", () => {
    expect(() => parseCaptureTraversalOptions({ maxPages: "2.5" })).toThrow();
  });
  it("rejects invalid booleans", () => {
    expect(() => parseCaptureTraversalOptions({ includeInfo: "yes" })).toThrow();
  });
  it("rejects leading zeros", () => {
    expect(() => parseCaptureTraversalOptions({ maxPages: "02" })).toThrow();
  });
});
describe("real work-item page traversal", () => {
  it("reads one complete page", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    expect(result.snapshot.cases).toHaveLength(1);
    expect(result.snapshot.complete).toBe(true);
  });
  it("reads two pages with a cursor", async () => {
    const load = loader(page(["a"], "next"), page(["b"]));
    const result = await traverseIntegrityCapture(scope, DEFAULT_CAPTURE_TRAVERSAL, load);
    expect(result.pagesRead).toBe(2);
    expect(result.snapshot.cases.map(x => x.workItemId)).toEqual(["a", "b"]);
  });
  it("passes trusted tenant and user scope to every read", async () => {
    const load = loader(page(["a"], "next"), page(["b"]));
    await traverseIntegrityCapture(scope, DEFAULT_CAPTURE_TRAVERSAL, load);
    expect(load).toHaveBeenNthCalledWith(1, scope, {
      limit: "50", includeInfo: "true", includeHistorical: "true",
    });
    expect(load).toHaveBeenNthCalledWith(2, scope, {
      limit: "50", includeInfo: "true", includeHistorical: "true",
      cursor: "next",
    });
  });
  it("stops when the cursor ends", async () => {
    const load = loader(page(["a"]));
    await traverseIntegrityCapture(scope, DEFAULT_CAPTURE_TRAVERSAL, load);
    expect(load).toHaveBeenCalledTimes(1);
  });
  it("stops at configured page limit", async () => {
    const load = loader(page(["a"], "next"));
    const result = await traverseIntegrityCapture(scope,
      { ...DEFAULT_CAPTURE_TRAVERSAL, maxPages: 1 }, load);
    expect(result.pagesRead).toBe(1);
    expect(result.hasMore).toBe(true);
    expect(result.snapshot.complete).toBe(false);
  });
  it("preserves continuation cursor when capped", async () => {
    const result = await traverseIntegrityCapture(scope,
      { ...DEFAULT_CAPTURE_TRAVERSAL, maxPages: 1 },
      loader(page(["a"], "next")));
    expect(result.nextCursor).toBe("next");
  });
  it("does not claim completeness with missing audit history", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a"], null, { historyComplete: false })));
    expect(result.historyComplete).toBe(false);
    expect(result.snapshot.complete).toBe(false);
  });
  it("does not claim completeness with missing linked coverage", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a"], null, { cases: [{ ...row("a"), completeCoverage: false }] })));
    expect(result.linkedCoverageComplete).toBe(false);
    expect(result.snapshot.complete).toBe(false);
  });
  it("does not claim completeness when informational diagnostics are excluded", async () => {
    const result = await traverseIntegrityCapture(scope,
      { ...DEFAULT_CAPTURE_TRAVERSAL, includeInfo: false },
      loader(page(["a"])));
    expect(result.snapshot.complete).toBe(false);
  });
  it("does not claim completeness when historical reviews are excluded", async () => {
    const result = await traverseIntegrityCapture(scope,
      { ...DEFAULT_CAPTURE_TRAVERSAL, includeHistorical: false },
      loader(page(["a"])));
    expect(result.snapshot.complete).toBe(false);
  });
  it("deduplicates identical cases across cursor pages", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a"], "next"), page(["a"])));
    expect(result.snapshot.cases).toHaveLength(1);
    expect(result.duplicateCases).toBe(1);
  });
  it("rejects conflicting duplicate records", async () => {
    const changed = { ...row("a"), taskRevision: 2 };
    await expect(traverseIntegrityCapture(scope, DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a"], "next"), page(["a"], null, { cases: [changed] }))))
      .rejects.toThrow("Conflicting case records");
  });
  it("rejects repeating a cursor", async () => {
    await expect(traverseIntegrityCapture(scope, DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a"], "loop"), page(["b"], "loop"))))
      .rejects.toThrow("Repeated work-item cursor");
  });
  it("rejects missing authenticated tenant", async () => {
    await expect(traverseIntegrityCapture({ ...scope, organizationId: "" },
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])))).rejects.toThrow();
  });
  it("rejects invalid traversal limit", async () => {
    await expect(traverseIntegrityCapture(scope,
      { ...DEFAULT_CAPTURE_TRAVERSAL, maxPages: 11 },
      loader(page(["a"])))).rejects.toThrow();
  });
  it("counts examined work items across pages", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a", "b"], "next"), page(["c"])));
    expect(result.workItemsExamined).toBe(3);
  });
  it("sorts output deterministically", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["z", "a", "m"])));
    expect(result.snapshot.cases.map(x => x.workItemId)).toEqual(["a", "m", "z"]);
  });
  it("preserves tenant identity in captured snapshot", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    expect(result.snapshot.organizationId).toBe("org-a");
  });
  it("encodes capture scope for later comparisons", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    expect(JSON.parse(result.snapshot.source).kind)
      .toBe("tenant-scoped-multi-page-case-capture");
  });
  it("can be compared to another capture of the same traversal scope", async () => {
    const first = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    const second = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    const report = compareIntegrityCaptures({
      before: first.snapshot, after: second.snapshot,
    }, "org-a");
    expect(report.counts.UNCHANGED).toBe(1);
  });
  it("rejects comparing captures with different page-size policies", async () => {
    const first = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    const second = await traverseIntegrityCapture(scope,
      { ...DEFAULT_CAPTURE_TRAVERSAL, pageSize: 100 }, loader(page(["a"])));
    expect(() => compareIntegrityCaptures({
      before: first.snapshot, after: second.snapshot,
    }, "org-a")).toThrow();
  });
  it("does not fabricate cases from an empty page", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page([])));
    expect(result.casesCollected).toBe(0);
    expect(result.snapshot.cases).toEqual([]);
  });
  it("preserves capture warnings", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL,
      loader(page(["a"], null, { limitations: ["Audit history is bounded"] })));
    expect(result.warnings).toContain("Audit history is bounded");
  });
  it("warns about sequential capture consistency", async () => {
    const result = await traverseIntegrityCapture(scope,
      DEFAULT_CAPTURE_TRAVERSAL, loader(page(["a"])));
    expect(result.warnings.some(w => w.includes("concurrent updates"))).toBe(true);
  });
});
