import { describe, expect, it } from "vitest";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import { buildIntegrityRemediationWorkspace } from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationExecutionEvents,
  buildIntegrityRemediationExecutionLedger,
} from "./work-integrity-remediation-execution";
import {
  buildIntegrityExecutionReviewHistory,
  buildIntegrityExecutionReviewAudit,
} from "./work-integrity-remediation-execution-review";
import {
  evaluateIntegrityExecutionPerformance,
  parseIntegrityExecutionPerformanceQuery,
  queryIntegrityExecutionPerformance,
  compareIntegrityExecutionPerformance,
} from "./work-integrity-remediation-execution-performance";
const input = {
  captureId: "capture-one",
  policies: [parseIntegrityEvidenceCoveragePolicy({
    captureId: "capture-one",
    rules: [{
      id: "required", caseKey: "case-one",
      minimumActiveWorkItems: 1, requiredWorkItemIds: ["work-one"],
    }],
  })],
};
const plan = buildIntegrityRemediationWorkspace(input, []).plan;
const candidateId = plan.candidates[0]!.id;
const decisions = [{
  candidateId, decision: "ACCEPT" as const, reason: "Approved",
  reviewerId: "reviewer", reviewedAt: "2026-11-01T00:00:00.000Z",
}];
const events = parseIntegrityRemediationExecutionEvents([
  {
    eventId: "event-one", candidateId, state: "REQUESTED",
    attemptId: "attempt-one", occurredAt: "2026-11-02T00:00:00.000Z",
    actorUserId: "actor-one", evidenceRefs: [], reason: "Started",
  },
  {
    eventId: "event-two", candidateId, state: "IN_PROGRESS",
    attemptId: "attempt-one", occurredAt: "2026-11-03T00:00:00.000Z",
    actorUserId: "actor-two", evidenceRefs: [], reason: "Working",
  },
  {
    eventId: "event-three", candidateId, state: "COMPLETED",
    attemptId: "attempt-one", occurredAt: "2026-11-04T00:00:00.000Z",
    actorUserId: "actor-two", evidenceRefs: ["evidence-one"], reason: "Done",
  },
]);
const checkpoints = [
  "2026-11-02T12:00:00.000Z",
  "2026-11-03T12:00:00.000Z",
  "2026-11-05T00:00:00.000Z",
];
function report() {
  const ledger = buildIntegrityRemediationExecutionLedger(plan, decisions, events);
  const history = buildIntegrityExecutionReviewHistory(
    plan, decisions, events, checkpoints);
  const audit = buildIntegrityExecutionReviewAudit(ledger, events);
  return evaluateIntegrityExecutionPerformance(
    ledger, history, audit, "2026-11-05T00:00:00.000Z");
}
describe("integrity execution performance", () => {
  it("measures completed and unverified work separately", () => {
    const result = report();
    expect(result.totals.completed).toBe(1);
    expect(result.totals.verified).toBe(0);
    expect(result.totals.verificationRate).toBe(0);
  });
  it("measures throughput across historical windows", () => {
    const result = report();
    expect(result.windows).toHaveLength(3);
    expect(result.windows[2]?.completed).toBe(1);
    expect(result.windows[2]?.throughputPerDay).toBeGreaterThan(0);
  });
  it("identifies unverified completion as a bottleneck", () => {
    const result = report();
    const item = result.bottlenecks.find(x => x.candidateId === candidateId);
    expect(item?.reasons).toContain("UNVERIFIED_COMPLETION");
  });
  it("attributes execution activity to actors", () => {
    const result = report();
    expect(result.actors.find(x => x.actorUserId === "actor-two")
      ?.completionEvents).toBe(1);
  });
  it("paginates bottlenecks with score filters", () => {
    const result = report();
    const query = parseIntegrityExecutionPerformanceQuery({
      onlyUnverified: true, minimumScore: 1, limit: 1,
    });
    const page = queryIntegrityExecutionPerformance(result, query);
    expect(page.total).toBe(1);
    expect(page.bottlenecks).toHaveLength(1);
  });
  it("rejects invalid query bounds", () => {
    expect(() => parseIntegrityExecutionPerformanceQuery({
      minimumScore: -1,
    })).toThrow();
  });
  it("compares risk and throughput snapshots", () => {
    const before = report();
    const after = { ...before,
      evaluatedAt: "2026-11-06T00:00:00.000Z",
      totals: { ...before.totals, outstandingRisk: 0 },
    };
    const comparison = compareIntegrityExecutionPerformance(before, after);
    expect(comparison.outstandingRiskDelta)
      .toBe(-before.totals.outstandingRisk);
  });
});
