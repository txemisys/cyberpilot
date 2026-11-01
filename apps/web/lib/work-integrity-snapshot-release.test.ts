import { describe, expect, it } from "vitest";
import { assessSnapshotRelease, assessSnapshotReleaseBatch } from "./work-integrity-snapshot-release";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const policy = {
  maxAgeDays: 40, requireComplete: true, requireQualityClearance: false,
  requireReview: false, requireBaseline: false, minCases: 0,
};
function capture(day: number, complete = true, organizationId = tenant, source = "source-a") {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
describe("snapshot release gates", () => {
  it("accepts a fresh complete capture under permissive policy", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now, policy, null, null);
    expect(result.eligible).toBe(true);
    expect(result.gates).toHaveLength(7);
  });
  it("blocks incomplete captures", () => {
    const result = assessSnapshotRelease(capture(31, false), tenant, now, policy, null, null);
    expect(result.eligible).toBe(false);
    expect(result.gates.find(g => g.gate === "COVERAGE")?.passed).toBe(false);
  });
  it("blocks future captures", () => {
    const result = assessSnapshotRelease({
      ...capture(31), capturedAt: "2026-11-02T12:00:00.000Z",
    }, tenant, now, policy, null, null);
    expect(result.gates.find(g => g.gate === "FRESHNESS")?.passed).toBe(false);
  });
  it("requires a real earlier baseline when configured", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now,
      { ...policy, requireBaseline: true }, null, capture(30));
    expect(result.eligible).toBe(true);
  });
  it("rejects a baseline from another source", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now,
      { ...policy, requireBaseline: true }, null, capture(30, true, tenant, "other"));
    expect(result.eligible).toBe(false);
  });
  it("rejects a baseline from another organization", () => {
    expect(() => assessSnapshotRelease(capture(31), tenant, now,
      policy, null, capture(30, true, "tenant-b"))).toThrow(/Cross-organization/);
  });
  it("requires explicit accepted review when configured", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now,
      { ...policy, requireReview: true }, null, null);
    expect(result.gates.find(g => g.gate === "REVIEW")?.passed).toBe(false);
  });
  it("accepts a review with a valid actor and time", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now,
      { ...policy, requireReview: true }, {
        status: "ACCEPTED", reviewerId: "reviewer-a",
        reviewedAt: "2026-11-01T10:00:00.000Z",
      }, null);
    expect(result.eligible).toBe(true);
  });
  it("rejects a future review timestamp", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now,
      { ...policy, requireReview: true }, {
        status: "ACCEPTED", reviewerId: "reviewer-a",
        reviewedAt: "2026-11-02T10:00:00.000Z",
      }, null);
    expect(result.eligible).toBe(false);
  });
  it("rejects a cross-tenant release", () => {
    expect(() => assessSnapshotRelease(capture(31, true, "tenant-b"),
      tenant, now, policy, null, null)).toThrow(/Cross-organization/);
  });
  it("enforces configured minimum case cardinality", () => {
    const result = assessSnapshotRelease(capture(31), tenant, now,
      { ...policy, minCases: 1 }, null, null);
    expect(result.eligible).toBe(false);
  });
});
describe("release batch", () => {
  it("evaluates several captures independently", () => {
    const result = assessSnapshotReleaseBatch([capture(30), capture(31, false)],
      tenant, now, policy);
    expect(result.assessed).toBe(2);
    expect(result.eligible).toBe(1);
    expect(result.blocked).toBe(1);
  });
  it("requires baseline for the first capture of each source", () => {
    const result = assessSnapshotReleaseBatch([capture(30), capture(31)],
      tenant, now, { ...policy, requireBaseline: true });
    expect(result.failedByGate.BASELINE).toBe(1);
  });
  it("rejects duplicate capture identities", () => {
    expect(() => assessSnapshotReleaseBatch([capture(31), capture(31)],
      tenant, now, policy)).toThrow(/Duplicate/);
  });
  it("does not mix organizations", () => {
    expect(() => assessSnapshotReleaseBatch([capture(31, true, "tenant-b")],
      tenant, now, policy)).toThrow(/Cross-organization/);
  });
});
