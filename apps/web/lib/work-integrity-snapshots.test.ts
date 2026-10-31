import { describe, expect, it } from "vitest";
import { compareCaseSnapshots, parseCaseSnapshot } from "./work-integrity-snapshots";
import type { CaseRow } from "./work-integrity-cases";

const row: CaseRow = {
  key: JSON.stringify(["work-1", "DONE_WITHOUT_COMPLETION", "work-1"]),
  workItemId: "work-1", code: "DONE_WITHOUT_COMPLETION", resourceId: "work-1",
  taskStatus: "DONE", taskRevision: 1, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Review history",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
};
const capture = (cases: CaseRow[], complete = true, organizationId = "org-a") => ({
  organizationId, source: "integrity-case-queue", capturedAt: "2026-10-31T12:00:00.000Z",
  complete, cases,
});
describe("integrity case snapshot parsing", () => {
  it("accepts a bounded valid snapshot", () => {
    expect(parseCaseSnapshot(capture([row])).cases).toHaveLength(1);
  });
  it.each([
    ["missing organization", { ...capture([]), organizationId: "" }],
    ["invalid time", { ...capture([]), capturedAt: "not-a-date" }],
    ["invalid source", { ...capture([]), source: "" }],
    ["invalid completeness", { ...capture([]), complete: "true" }],
    ["duplicate case", capture([row, row])],
    ["mismatched key", capture([{ ...row, key: "wrong" }])],
    ["invalid revision", capture([{ ...row, taskRevision: 0 }])],
    ["invalid reviewed revision", capture([{ ...row, reviewedRevision: -1 }])],
    ["invalid state", capture([{ ...row, state: "RESOLVED" as never }])],
    ["invalid severity", capture([{ ...row, severity: "unknown" as never }])],
    ["invalid coverage", capture([{ ...row, completeCoverage: "true" as never }])],
    ["invalid work ID", capture([{ ...row, workItemId: "" }])],
    ["invalid diagnostic", capture([{ ...row, diagnostic: 123 as never }])],
    ["invalid reviewer", capture([{ ...row, reviewerUserId: 123 as never }])],
  ])("rejects %s", (_, input) => {
    expect(() => parseCaseSnapshot(input as unknown)).toThrow();
  });
  it("enforces case count bounds", () => {
    expect(() => parseCaseSnapshot(capture([row]), 0)).toThrow();
  });
});
describe("integrity case snapshot comparisons", () => {
  it("reports newly detected case when both snapshots are complete", () => {
    const result = compareCaseSnapshots(capture([]), capture([row]));
    expect(result.counts.NEW).toBe(1);
    expect(result.deltas[0]?.kind).toBe("NEW");
  });
  it("reports cleared case only with complete snapshots", () => {
    const result = compareCaseSnapshots(capture([row]), capture([]));
    expect(result.counts.CLEARED).toBe(1);
  });
  it("does not claim clearance with incomplete after snapshot", () => {
    const result = compareCaseSnapshots(capture([row]), capture([], false));
    expect(result.counts.INDETERMINATE).toBe(1);
    expect(result.counts.CLEARED).toBe(0);
  });
  it("does not claim new detection with incomplete before snapshot", () => {
    const result = compareCaseSnapshots(capture([], false), capture([row]));
    expect(result.counts.INDETERMINATE).toBe(1);
    expect(result.counts.NEW).toBe(0);
  });
  it("detects a changed case review", () => {
    const reviewed = { ...row, state: "INVESTIGATING" as const,
      reviewEventId: "audit-1", reviewedRevision: 1 };
    const result = compareCaseSnapshots(capture([row]), capture([reviewed]));
    expect(result.counts.CHANGED).toBe(1);
    expect(result.deltas[0]?.changes).toEqual([
      "state", "reviewEventId", "reviewedRevision",
    ]);
  });
  it("reports unchanged case", () => {
    expect(compareCaseSnapshots(capture([row]), capture([row])).counts.UNCHANGED).toBe(1);
  });
  it("rejects cross-tenant comparisons", () => {
    expect(() => compareCaseSnapshots(capture([row]), capture([row], true, "org-b"))).toThrow();
  });
  it("does not confuse same code on different resources", () => {
    const other = { ...row, resourceId: "work-2",
      key: JSON.stringify(["work-1", "DONE_WITHOUT_COMPLETION", "work-2"]) };
    const result = compareCaseSnapshots(capture([row]), capture([other]));
    expect(result.counts.NEW).toBe(1);
    expect(result.counts.CLEARED).toBe(1);
  });
  it("preserves deterministic key ordering", () => {
    const other = { ...row, workItemId: "work-2", resourceId: "work-2",
      key: JSON.stringify(["work-2", "DONE_WITHOUT_COMPLETION", "work-2"]) };
    const result = compareCaseSnapshots(capture([other, row]), capture([row, other]));
    expect(result.deltas.map(x => x.key)).toEqual([row.key, other.key]);
  });
});
