import { describe, expect, it } from "vitest";
import { createReadinessWorkQueue } from "./work-integrity-snapshot-readiness-work";
import { planReadinessWorkExecution } from "./work-integrity-snapshot-readiness-execution";
import type { SnapshotReadinessReport } from "./work-integrity-snapshot-readiness";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const report = {
  version: 1, organizationId: tenant,
  checks: [{ id: "SOURCE_COVERAGE", decision: "BLOCK" }],
  nextActions: [
    { priority: "IMMEDIATE", source: "source-a",
      action: "Collect the source.", relatedChecks: ["SOURCE_COVERAGE"] },
    { priority: "IMMEDIATE", source: "source-b",
      action: "Verify the source.", relatedChecks: ["SOURCE_COVERAGE"] },
  ],
} as unknown as SnapshotReadinessReport;
const workPolicy = {
  maxItems: 100, p0DueHours: 4, p1DueHours: 24,
  p2DueHours: 72, p3DueHours: 168,
  requireEvidenceForCompletion: true, allowDismissBlockers: false,
  preserveExistingStates: true, allowUnassignedItems: true,
  minimumResolutionCharacters: 10,
};
const policy = {
  maxItems: 100, maxDependenciesPerItem: 10, maxStages: 20,
  requirePredecessorCompletion: true, includeDismissedAsCompleted: false,
  blockOnOverduePredecessor: true,
};
function queue() {
  return createReadinessWorkQueue(report, tenant, now, workPolicy);
}
describe("readiness execution dependency graph", () => {
  it("plans independent work in the first stage", () => {
    const plan = planReadinessWorkExecution(queue(), tenant, now, policy);
    expect(plan.stages).toHaveLength(1);
    expect(plan.actionableItems).toBe(2);
  });
  it("schedules a dependent task after its predecessor", () => {
    const original = queue();
    const items = original.items.map((item, index) => index === 1 ?
      { ...item, dependencies: [original.items[0]!.id] } : item);
    const plan = planReadinessWorkExecution({ ...original, items },
      tenant, now, { ...policy, requirePredecessorCompletion: false });
    expect(plan.stages).toHaveLength(2);
  });
  it("blocks a task whose predecessor has not completed", () => {
    const original = queue();
    const items = original.items.map((item, index) => index === 1 ?
      { ...item, dependencies: [original.items[0]!.id] } : item);
    const plan = planReadinessWorkExecution({ ...original, items }, tenant, now, policy);
    expect(plan.findings.map(finding => finding.issue))
      .toContain("UNRESOLVED_PREDECESSOR");
  });
  it("detects self dependencies", () => {
    const original = queue();
    const items = original.items.map((item, index) => index === 0 ?
      { ...item, dependencies: [item.id] } : item);
    const plan = planReadinessWorkExecution({ ...original, items }, tenant, now, policy);
    expect(plan.findings.map(finding => finding.issue)).toContain("SELF_DEPENDENCY");
    expect(plan.executable).toBe(false);
  });
  it("detects circular dependencies", () => {
    const original = queue();
    const items = original.items.map((item, index) => ({
      ...item, dependencies: [original.items[1 - index]!.id],
    }));
    const plan = planReadinessWorkExecution({ ...original, items }, tenant, now, policy);
    expect(plan.findings.map(finding => finding.issue)).toContain("CYCLIC_DEPENDENCY");
  });
  it("reports missing predecessors", () => {
    const original = queue();
    const items = original.items.map((item, index) => index === 0 ?
      { ...item, dependencies: ["missing-item"] } : item);
    const plan = planReadinessWorkExecution({ ...original, items }, tenant, now, policy);
    expect(plan.findings.map(finding => finding.issue)).toContain("MISSING_DEPENDENCY");
  });
  it("rejects cross-tenant execution", () => {
    expect(() => planReadinessWorkExecution(queue(), "tenant-b", now, policy))
      .toThrow(/Cross-organization/);
  });
  it("produces deterministic plan digests", () => {
    expect(planReadinessWorkExecution(queue(), tenant, now, policy).planDigest)
      .toBe(planReadinessWorkExecution(queue(), tenant, now, policy).planDigest);
  });
  it("rejects invalid dependency limits", () => {
    expect(() => planReadinessWorkExecution(queue(), tenant, now, {
      ...policy, maxDependenciesPerItem: -1,
    })).toThrow(/Invalid/);
  });
  it("does not claim real-world remediation execution", () => {
    expect(planReadinessWorkExecution(queue(), tenant, now, policy).limitations
      .some(item => item.includes("do not execute"))).toBe(true);
  });
});
