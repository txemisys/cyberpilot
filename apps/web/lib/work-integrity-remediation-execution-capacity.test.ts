import { describe, expect, it } from "vitest";
import {
  parseIntegrityExecutionCapacityMembers,
  parseIntegrityExecutionCapacityPolicy,
  planIntegrityExecutionCapacity,
  queryIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityQuery,
} from "./work-integrity-remediation-execution-capacity";
import {
  forecastIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityForecastPolicy,
  parseIntegrityExecutionCapacityForecastQuery,
  queryIntegrityExecutionCapacityForecast,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";
const queue: IntegrityExecutionRemediationQueue = {
  schemaVersion: 1, captureId: "capture-one",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  limitation: "Diagnostic only",
  policy: {
    priorityWeights: { P0: 100 }, blockerWeights: {
      UNKNOWN_CANDIDATE: 100, NOT_APPROVED: 25,
      CONTROL_ERROR: 80, CONTROL_WARNING: 10,
      PROVENANCE_ERROR: 75, PROVENANCE_WARNING: 10,
      NO_ACTIVE_ASSOCIATION: 55, NO_COMPLETION_REFERENCE: 45,
      EXECUTION_NOT_COMPLETED: 20, EXECUTION_FAILED: 70,
      EXECUTION_BLOCKED: 50, EXECUTION_CANCELLED: 35,
      UNVERIFIED_EVIDENCE: 65, UNBOUND_WORK_ITEM: 40,
      MISSING_EXECUTION_CONTROLS: 90, MISSING_PROVENANCE: 90,
    },
    agingDays: 7, agingPointsPerPeriod: 5, maximumAgingPoints: 40,
    maximumQueueSize: 10000, includeReady: false,
  },
  items: [
    {
      candidateId: "candidate-one", caseKey: "case-one",
      workItemId: "work-one", priority: "P0",
      action: "LINK_REQUIRED_WORK", state: "BLOCKED",
      ready: false, blockers: ["CONTROL_ERROR"],
      score: 180, priorityPoints: 100, blockerPoints: 80,
      agingPoints: 0, firstBlockedAt: null,
      lastChangedAt: null, blockedDays: 0,
      attentionReasons: ["control error"],
      recommendedNextStep: "REVIEW_EXECUTION_CONTROLS",
    },
    {
      candidateId: "candidate-two", caseKey: "case-two",
      workItemId: "work-two", priority: "P1",
      action: "LINK_REQUIRED_WORK", state: "NOT_STARTED",
      ready: false, blockers: ["NOT_APPROVED"],
      score: 95, priorityPoints: 70, blockerPoints: 25,
      agingPoints: 0, firstBlockedAt: null,
      lastChangedAt: null, blockedDays: 0,
      attentionReasons: ["not approved"],
      recommendedNextStep: "REQUEST_REMEDIATION_APPROVAL",
    },
  ],
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
const members = parseIntegrityExecutionCapacityMembers([
  {
    actorUserId: "actor-one", maximumConcurrent: 1,
    maximumPoints: 5, supportedActions: ["LINK_REQUIRED_WORK"],
    supportedSteps: [], excludedCaseKeys: [], assignedCandidateIds: [],
  },
  {
    actorUserId: "actor-two", maximumConcurrent: 2,
    maximumPoints: 10, supportedActions: [],
    supportedSteps: [], excludedCaseKeys: [],
    assignedCandidateIds: [],
  },
]);
describe("execution capacity planning", () => {
  it("distributes candidates without exceeding concurrent slots", () => {
    const result = planIntegrityExecutionCapacity(
      queue, members, "2026-11-03T00:00:00.000Z");
    expect(result.totals.assigned).toBe(2);
    expect(result.members.every(x => x.remainingSlots >= 0)).toBe(true);
    expect(new Set(result.assignments.map(x => x.candidateId)).size).toBe(2);
  });
  it("respects existing assignments", () => {
    const assigned = members.map(x => ({
      ...x, assignedCandidateIds:
        x.actorUserId === "actor-two" ? ["candidate-one"] : [],
    }));
    const result = planIntegrityExecutionCapacity(
      queue, assigned, "2026-11-03T00:00:00.000Z");
    expect(result.assignments.find(x =>
      x.candidateId === "candidate-one")?.actorUserId).toBe("actor-two");
  });
  it("rejects ambiguous existing assignment ownership", () => {
    const assigned = members.map(x => ({
      ...x, assignedCandidateIds: ["candidate-one"],
    }));
    expect(() => planIntegrityExecutionCapacity(
      queue, assigned, "2026-11-03T00:00:00.000Z")).toThrow();
  });
  it("validates effort weights and filters", () => {
    expect(() => parseIntegrityExecutionCapacityPolicy({
      effortByAction: { LINK_REQUIRED_WORK: 0 },
    })).toThrow();
    expect(() => parseIntegrityExecutionCapacityQuery({
      source: ["FAKE"],
    })).toThrow();
  });
  it("queries proposed assignments", () => {
    const result = planIntegrityExecutionCapacity(
      queue, members, "2026-11-03T00:00:00.000Z");
    const page = queryIntegrityExecutionCapacity(result,
      parseIntegrityExecutionCapacityQuery({
        source: ["PROPOSED"], limit: 1,
      }));
    expect(page.total).toBe(2);
    expect(page.hasMore).toBe(true);
  });
});
describe("execution capacity forecast", () => {
  it("forecasts completed assignments without mutating work", () => {
    const plan = planIntegrityExecutionCapacity(
      queue, members, "2026-11-03T00:00:00.000Z");
    const forecast = forecastIntegrityExecutionCapacity(
      plan, queue, "2026-11-03T00:00:00.000Z");
    expect(forecast.totals.completedWithinHorizon).toBe(2);
    expect(forecast.tasks.every(x => x.status === "SCHEDULED")).toBe(true);
  });
  it("identifies assignments outside a short horizon", () => {
    const plan = planIntegrityExecutionCapacity(
      queue, members, "2026-11-03T00:00:00.000Z");
    const forecast = forecastIntegrityExecutionCapacity(
      plan, queue, "2026-11-03T00:00:00.000Z",
      parseIntegrityExecutionCapacityForecastPolicy({
        maximumForecastDays: 1, pointsPerDay: 1,
      }));
    expect(forecast.totals.outsideHorizon).toBeGreaterThan(0);
  });
  it("validates forecast query statuses", () => {
    expect(() => parseIntegrityExecutionCapacityForecastQuery({
      statuses: ["SECURITY_VERIFIED"],
    })).toThrow();
  });
  it("queries capacity-unavailable tasks", () => {
    const plan = planIntegrityExecutionCapacity(
      queue, [], "2026-11-03T00:00:00.000Z");
    const forecast = forecastIntegrityExecutionCapacity(
      plan, queue, "2026-11-03T00:00:00.000Z");
    const page = queryIntegrityExecutionCapacityForecast(forecast,
      parseIntegrityExecutionCapacityForecastQuery({
        statuses: ["CAPACITY_UNAVAILABLE"],
      }));
    expect(page.total).toBe(2);
  });
});
