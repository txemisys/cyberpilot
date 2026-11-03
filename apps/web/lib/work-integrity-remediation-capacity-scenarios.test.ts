import { describe, expect, it } from "vitest";
import {
  parseIntegrityCapacityScenarios,
  compareIntegrityCapacityScenarios,
  parseIntegrityCapacityScenarioQuery,
  queryIntegrityCapacityScenarios,
} from "./work-integrity-remediation-capacity-scenarios";
import {
  diagnoseIntegrityExecutionCapacity,
  parseIntegrityCapacityBottleneckPolicy,
  parseIntegrityCapacityBottleneckQuery,
  queryIntegrityCapacityBottlenecks,
} from "./work-integrity-remediation-capacity-bottlenecks";
import {
  planIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityMembers,
} from "./work-integrity-remediation-execution-capacity";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";
const queue: IntegrityExecutionRemediationQueue = {
  schemaVersion: 1, captureId: "capture-one",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  limitation: "Diagnostic only",
  policy: {
    priorityWeights: { P0: 100 },
    blockerWeights: {
      UNKNOWN_CANDIDATE: 100, NOT_APPROVED: 25,
      CONTROL_ERROR: 80, CONTROL_WARNING: 10,
      PROVENANCE_ERROR: 75, PROVENANCE_WARNING: 10,
      NO_ACTIVE_ASSOCIATION: 55, NO_COMPLETION_REFERENCE: 45,
      EXECUTION_NOT_COMPLETED: 20, EXECUTION_FAILED: 70,
      EXECUTION_BLOCKED: 50, EXECUTION_CANCELLED: 35,
      UNVERIFIED_EVIDENCE: 65, UNBOUND_WORK_ITEM: 40,
      MISSING_EXECUTION_CONTROLS: 90, MISSING_PROVENANCE: 90,
    },
    agingDays: 7, agingPointsPerPeriod: 5,
    maximumAgingPoints: 40, maximumQueueSize: 10000,
    includeReady: false,
  },
  items: [{
    candidateId: "one", caseKey: "case-one",
    workItemId: "work-one", priority: "P0",
    action: "LINK_REQUIRED_WORK", state: "BLOCKED",
    ready: false, blockers: ["CONTROL_ERROR"],
    score: 180, priorityPoints: 100, blockerPoints: 80,
    agingPoints: 0, firstBlockedAt: null,
    lastChangedAt: null, blockedDays: 0,
    attentionReasons: ["control error"],
    recommendedNextStep: "REVIEW_EXECUTION_CONTROLS",
  }, {
    candidateId: "two", caseKey: "case-two",
    workItemId: "work-two", priority: "P1",
    action: "REVIEW_AUDIT_ERROR", state: "BLOCKED",
    ready: false, blockers: ["NOT_APPROVED"],
    score: 95, priorityPoints: 70, blockerPoints: 25,
    agingPoints: 0, firstBlockedAt: null,
    lastChangedAt: null, blockedDays: 0,
    attentionReasons: ["not approved"],
    recommendedNextStep: "REQUEST_REMEDIATION_APPROVAL",
  }],
  totals: {
    candidates: 2, queued: 2, omittedReady: 0,
    withHistory: 0, withoutHistory: 2,
    urgent: 0, high: 1, normal: 1, low: 0,
    totalScore: 275, averageScore: 138,
    maximumScore: 180, oldestBlockedDays: 0,
    byNextStep: {
      REVIEW_EXECUTION_CONTROLS: 1,
      REQUEST_REMEDIATION_APPROVAL: 1,
    },
  },
};
const scenarioInputs = [
  {
    scenarioId: "none", label: "No staff", members: [],
  },
  {
    scenarioId: "staffed", label: "One owner",
    members: [{
      actorUserId: "owner-one", maximumConcurrent: 2,
      maximumPoints: 10, supportedActions: [],
      supportedSteps: [], excludedCaseKeys: [],
      assignedCandidateIds: [],
    }],
  },
];
const at = "2026-11-03T00:00:00.000Z";
describe("capacity what-if scenarios", () => {
  it("compares assignment and completion against baseline", () => {
    const scenarios = parseIntegrityCapacityScenarios(scenarioInputs);
    const result = compareIntegrityCapacityScenarios(queue, scenarios, at);
    expect(result.baselineScenarioId).toBe("none");
    expect(result.bestByAssigned).toBe("staffed");
    expect(result.scenarios[1]?.delta.assignedDelta).toBe(2);
    expect(result.scenarios[1]?.delta.gainedCandidateIds).toEqual(["one", "two"]);
  });
  it("supports Pareto filtering and pagination", () => {
    const result = compareIntegrityCapacityScenarios(
      queue, parseIntegrityCapacityScenarios(scenarioInputs), at);
    const page = queryIntegrityCapacityScenarios(result,
      parseIntegrityCapacityScenarioQuery({
        onlyPareto: true, limit: 1,
      }));
    expect(page.total).toBe(1);
    expect(page.scenarios[0]?.scenarioId).toBe("staffed");
  });
  it("rejects duplicated scenario IDs", () => {
    expect(() => parseIntegrityCapacityScenarios([
      scenarioInputs[0], scenarioInputs[0],
    ])).toThrow();
  });
  it("rejects unknown baseline", () => {
    expect(() => compareIntegrityCapacityScenarios(
      queue, parseIntegrityCapacityScenarios(scenarioInputs),
      at, "missing")).toThrow();
  });
});
describe("capacity bottleneck diagnostics", () => {
  it("identifies lack of available owners", () => {
    const plan = planIntegrityExecutionCapacity(queue, [], at);
    const result = diagnoseIntegrityExecutionCapacity(queue, plan, null);
    expect(result.bottlenecks.some(x =>
      x.kind === "NO_AVAILABLE_OWNER")).toBe(true);
    expect(result.totals.distinctAffectedCandidates).toBe(2);
  });
  it("does not report bottlenecks for fully allocated queue", () => {
    const members = parseIntegrityExecutionCapacityMembers(
      scenarioInputs[1]!.members);
    const plan = planIntegrityExecutionCapacity(queue, members, at);
    const result = diagnoseIntegrityExecutionCapacity(queue, plan, null);
    expect(result.totals.bottlenecks).toBe(0);
  });
  it("filters diagnostics by kind", () => {
    const plan = planIntegrityExecutionCapacity(queue, [], at);
    const report = diagnoseIntegrityExecutionCapacity(queue, plan, null);
    const page = queryIntegrityCapacityBottlenecks(report,
      parseIntegrityCapacityBottleneckQuery({
        kinds: ["NO_AVAILABLE_OWNER"],
      }));
    expect(page.total).toBe(1);
  });
  it("rejects unknown diagnostic filters", () => {
    expect(() => parseIntegrityCapacityBottleneckQuery({
      kinds: ["INVENTED"],
    })).toThrow();
  });
  it("rejects inverted severity thresholds", () => {
    expect(() => parseIntegrityCapacityBottleneckPolicy({
      highCandidateThreshold: 20,
      criticalCandidateThreshold: 5,
    })).toThrow();
  });
});
