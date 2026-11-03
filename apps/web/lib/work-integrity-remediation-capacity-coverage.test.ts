import { describe, expect, it } from "vitest";
import {
  buildIntegrityCapacityCoverage,
  parseIntegrityCapacityCoverageQuery,
  queryIntegrityCapacityCoverage,
} from "./work-integrity-remediation-capacity-coverage";
import {
  planIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityMembers,
} from "./work-integrity-remediation-execution-capacity";
import {
  forecastIntegrityExecutionCapacity,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";
const at = "2026-11-03T00:00:00.000Z";
const queue: IntegrityExecutionRemediationQueue = {
  schemaVersion: 1, captureId: "capture-one",
  evaluatedAt: at, limitation: "Diagnostic only",
  policy: {
    priorityWeights: {}, blockerWeights: {
      UNKNOWN_CANDIDATE: 0, NOT_APPROVED: 0,
      CONTROL_ERROR: 0, CONTROL_WARNING: 0,
      PROVENANCE_ERROR: 0, PROVENANCE_WARNING: 0,
      NO_ACTIVE_ASSOCIATION: 0, NO_COMPLETION_REFERENCE: 0,
      EXECUTION_NOT_COMPLETED: 0, EXECUTION_FAILED: 0,
      EXECUTION_BLOCKED: 0, EXECUTION_CANCELLED: 0,
      UNVERIFIED_EVIDENCE: 0, UNBOUND_WORK_ITEM: 0,
      MISSING_EXECUTION_CONTROLS: 0, MISSING_PROVENANCE: 0,
    },
    agingDays: 7, agingPointsPerPeriod: 5,
    maximumAgingPoints: 40, maximumQueueSize: 10000,
    includeReady: false,
  },
  items: [{
    candidateId: "candidate-one", caseKey: "case-one",
    workItemId: "work-one", priority: "P0",
    action: "LINK_REQUIRED_WORK", state: "BLOCKED",
    ready: false, blockers: ["CONTROL_ERROR"],
    score: 180, priorityPoints: 100, blockerPoints: 80,
    agingPoints: 0, firstBlockedAt: null,
    lastChangedAt: null, blockedDays: 0,
    attentionReasons: ["control error"],
    recommendedNextStep: "REVIEW_EXECUTION_CONTROLS",
  }],
  totals: {
    candidates: 1, queued: 1, omittedReady: 0,
    withHistory: 0, withoutHistory: 1,
    urgent: 0, high: 1, normal: 0, low: 0,
    totalScore: 180, averageScore: 180,
    maximumScore: 180, oldestBlockedDays: 0,
    byNextStep: { REVIEW_EXECUTION_CONTROLS: 1 },
  },
};
describe("capacity coverage", () => {
  it("groups assignments by case and priority", () => {
    const members = parseIntegrityExecutionCapacityMembers([{
      actorUserId: "owner", maximumConcurrent: 1,
      maximumPoints: 10, supportedActions: [],
      supportedSteps: [], excludedCaseKeys: [],
      assignedCandidateIds: [],
    }]);
    const plan = planIntegrityExecutionCapacity(queue, members, at);
    const forecast = forecastIntegrityExecutionCapacity(plan, queue, at);
    const report = buildIntegrityCapacityCoverage(queue, plan, forecast);
    expect(report.totals.assigned).toBe(1);
    expect(report.dimensions.CASE[0]?.key).toBe("case-one");
    expect(report.dimensions.PRIORITY[0]?.completedWithinHorizon).toBe(1);
  });
  it("flags unavailable assignments without owners", () => {
    const plan = planIntegrityExecutionCapacity(queue, [], at);
    const forecast = forecastIntegrityExecutionCapacity(plan, queue, at);
    const report = buildIntegrityCapacityCoverage(queue, plan, forecast);
    expect(report.uncovered.unassignedCandidateIds)
      .toEqual(["candidate-one"]);
    expect(report.totals.unavailable).toBe(1);
  });
  it("filters uncovered groups by dimension", () => {
    const plan = planIntegrityExecutionCapacity(queue, [], at);
    const report = buildIntegrityCapacityCoverage(queue, plan, null);
    const page = queryIntegrityCapacityCoverage(report,
      parseIntegrityCapacityCoverageQuery({
        dimensions: ["CASE"], onlyUncovered: true,
      }));
    expect(page.total).toBe(1);
  });
  it("rejects unknown coverage dimensions", () => {
    expect(() => parseIntegrityCapacityCoverageQuery({
      dimensions: ["SECRET"],
    })).toThrow();
  });
  it("rejects incomplete assignment records", () => {
    const plan = planIntegrityExecutionCapacity(queue, [], at);
    expect(() => buildIntegrityCapacityCoverage(queue, {
      ...plan, unassigned: [],
    }, null)).toThrow();
  });
});
