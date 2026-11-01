import { describe, expect, it } from "vitest";
import { planSnapshotRetention, validateRetentionPolicy } from "./work-integrity-snapshot-retention";

const policy = {
  maxAgeDays: 7,
  minRecentCaptures: 1,
  maxRetainedCaptures: 1,
  preserveMonthlyBaselines: false,
  preserveFirstComplete: false,
};
function capture(day: number, source = "queue", complete = true, organizationId = "tenant-a") {
  return {
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
    organizationId, source, complete, cases: [],
  };
}
const now = "2026-11-01T12:00:00.000Z";
describe("snapshot retention planner", () => {
  it("never mixes organizations", () => {
    expect(() => planSnapshotRetention([capture(1, "queue", true, "tenant-b")],
      "tenant-a", now, policy)).toThrow(/Cross-organization/);
  });
  it("protects the most recent capture even when old", () => {
    const plan = planSnapshotRetention([capture(1)], "tenant-a", now, policy);
    expect(plan.retained).toBe(1);
    expect(plan.decisions[0]?.reasons).toContain("recent-capture-floor");
  });
  it("marks old captures as eligible but does not delete anything", () => {
    const plan = planSnapshotRetention([capture(1), capture(2), capture(3)],
      "tenant-a", now, policy);
    expect(plan.eligibleForDeletion).toBe(2);
    expect(plan.decisions.find(d => d.capturedAt.includes("-03T"))?.action).toBe("KEEP");
  });
  it("preserves the oldest complete capture independently of recent floor", () => {
    const plan = planSnapshotRetention([capture(1), capture(2, "queue", false), capture(3)],
      "tenant-a", now, { ...policy, preserveFirstComplete: true });
    expect(plan.decisions.find(d => d.capturedAt.includes("-01T"))?.reasons)
      .toContain("first-complete-baseline");
  });
  it("warns when no complete baseline is available", () => {
    const plan = planSnapshotRetention([capture(1, "queue", false)],
      "tenant-a", now, { ...policy, preserveFirstComplete: true });
    expect(plan.warnings).toHaveLength(1);
  });
  it("keeps a complete monthly baseline over an incomplete one", () => {
    const plan = planSnapshotRetention([capture(1), capture(2, "queue", false), capture(3)],
      "tenant-a", now, { ...policy, preserveMonthlyBaselines: true });
    expect(plan.decisions.find(d => d.capturedAt.includes("-03T"))?.reasons)
      .toContain("monthly-baseline");
  });
  it("isolates retention quotas by source", () => {
    const plan = planSnapshotRetention([capture(1, "a"), capture(2, "a"),
      capture(1, "b"), capture(2, "b")], "tenant-a", now, policy);
    expect(plan.retained).toBe(2);
    expect(plan.eligibleForDeletion).toBe(2);
  });
  it("rejects future captures", () => {
    expect(() => planSnapshotRetention([{
      ...capture(1), capturedAt: "2027-01-01T00:00:00.000Z",
    }], "tenant-a", now, policy)).toThrow(/Future/);
  });
  it("rejects duplicate source timestamps", () => {
    expect(() => planSnapshotRetention([capture(1), capture(1)],
      "tenant-a", now, policy)).toThrow(/Duplicate/);
  });
  it("rejects invalid policy limits", () => {
    expect(() => validateRetentionPolicy({ ...policy, maxAgeDays: 0 }))
      .toThrow(/retention age/);
  });
  it("does not exceed a safety cap by deleting protected baselines", () => {
    const plan = planSnapshotRetention([capture(1), capture(2), capture(3)],
      "tenant-a", now, { ...policy, minRecentCaptures: 3 });
    expect(plan.retained).toBe(3);
    expect(plan.warnings.some(w => w.includes("exceeding"))).toBe(true);
  });
  it("rejects invalid evaluation dates", () => {
    expect(() => planSnapshotRetention([], "tenant-a", "not-a-date", policy))
      .toThrow(/evaluation time/);
  });
});
