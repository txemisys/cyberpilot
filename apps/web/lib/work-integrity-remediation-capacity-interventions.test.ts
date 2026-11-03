import { describe, expect, it } from "vitest";
import {
  parseIntegrityCapacityInterventions,
  parseIntegrityCapacityInterventionQuery,
  queryIntegrityCapacityInterventions,
  simulateIntegrityCapacityInterventions,
} from "./work-integrity-remediation-capacity-interventions";
import {
  parseIntegrityCapacityPortfolioPolicy,
  parseIntegrityCapacityPortfolioQuery,
  queryIntegrityCapacityPortfolio,
  evaluateIntegrityCapacityPortfolio,
} from "./work-integrity-remediation-capacity-portfolio";
import {
  parseIntegrityExecutionCapacityMembers,
  parseIntegrityExecutionCapacityPolicy,
} from "./work-integrity-remediation-execution-capacity";
import {
  parseIntegrityExecutionCapacityForecastPolicy,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";
const at = "2026-11-03T00:00:00.000Z";
const queue: IntegrityExecutionRemediationQueue = {
  schemaVersion: 1, captureId: "capture-one",
  evaluatedAt: at, limitation: "Analytical",
  policy: {
    priorityWeights: {},
    blockerWeights: {
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
const members = parseIntegrityExecutionCapacityMembers([{
  actorUserId: "owner-one", maximumConcurrent: 0,
  maximumPoints: 10, supportedActions: [],
  supportedSteps: [], excludedCaseKeys: [],
  assignedCandidateIds: [],
}]);
const capacityPolicy = parseIntegrityExecutionCapacityPolicy(undefined);
const forecastPolicy = parseIntegrityExecutionCapacityForecastPolicy(undefined);
const interventions = parseIntegrityCapacityInterventions([
  {
    interventionId: "more-slots", kind: "INCREASE_SLOTS",
    actorUserId: "owner-one", additionalSlots: 1,
  },
  {
    interventionId: "more-points", kind: "INCREASE_POINTS",
    actorUserId: "owner-one", additionalPoints: 5,
  },
]);
describe("capacity interventions", () => {
  it("simulates slot expansion without mutating inputs", () => {
    const report = simulateIntegrityCapacityInterventions(
      queue, members, at, capacityPolicy, forecastPolicy, interventions);
    expect(report.baseline.assigned).toBe(0);
    expect(report.outcomes.find(x =>
      x.interventionId === "more-slots")?.assignedDelta).toBe(1);
    expect(report.outcomes.find(x =>
      x.interventionId === "more-points")?.assignedDelta).toBe(0);
    expect(members[0]?.maximumConcurrent).toBe(0);
  });
  it("filters improved interventions", () => {
    const report = simulateIntegrityCapacityInterventions(
      queue, members, at, capacityPolicy, forecastPolicy, interventions);
    const page = queryIntegrityCapacityInterventions(report,
      parseIntegrityCapacityInterventionQuery({
        onlyImproved: true,
      }));
    expect(page.total).toBe(1);
    expect(page.outcomes[0]?.interventionId).toBe("more-slots");
  });
  it("rejects unknown intervention kinds", () => {
    expect(() => parseIntegrityCapacityInterventions([{
      interventionId: "bad", kind: "GRANT_ADMIN",
    }])).toThrow();
  });
  it("rejects duplicate intervention IDs", () => {
    expect(() => parseIntegrityCapacityInterventions([
      {
        interventionId: "same", kind: "INCREASE_CASE_LIMIT",
        additionalLimit: 1,
      },
      {
        interventionId: "same", kind: "INCREASE_CASE_LIMIT",
        additionalLimit: 2,
      },
    ])).toThrow();
  });
});
describe("capacity portfolio", () => {
  it("evaluates combinations and preserves the baseline", () => {
    const report = evaluateIntegrityCapacityPortfolio(
      queue, members, at, capacityPolicy, forecastPolicy,
      interventions, parseIntegrityCapacityPortfolioPolicy(undefined));
    expect(report.baseline.assigned).toBe(0);
    expect(report.bundles.some(x =>
      x.interventionIds.includes("more-slots") &&
      x.assignedDelta === 1)).toBe(true);
    expect(report.recommendedBundleIds.length).toBeGreaterThan(0);
  });
  it("filters non-degrading Pareto bundles", () => {
    const report = evaluateIntegrityCapacityPortfolio(
      queue, members, at, capacityPolicy, forecastPolicy, interventions);
    const page = queryIntegrityCapacityPortfolio(report,
      parseIntegrityCapacityPortfolioQuery({
        onlyPareto: true, onlyNonDegrading: true,
      }));
    expect(page.total).toBeGreaterThan(0);
  });
  it("enforces a bounded evaluation budget", () => {
    const report = evaluateIntegrityCapacityPortfolio(
      queue, members, at, capacityPolicy, forecastPolicy,
      interventions, parseIntegrityCapacityPortfolioPolicy({
        maximumEvaluations: 1,
      }));
    expect(report.totals.truncated).toBe(true);
  });
  it("rejects unknown query keys", () => {
    expect(() => parseIntegrityCapacityPortfolioQuery({
      executeAutomatically: true,
    })).toThrow();
  });
});
