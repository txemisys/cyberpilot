import { describe, expect, it } from "vitest";
import {
  decideIntegrityCapacityPortfolio,
  parseIntegrityCapacityDecisionPolicy,
  auditIntegrityCapacityDecision,
} from "./work-integrity-remediation-capacity-decision";
import {
  compareIntegrityCapacityDecisionPolicies,
  parseIntegrityCapacityDecisionComparisonQuery,
  queryIntegrityCapacityDecisionComparison,
} from "./work-integrity-remediation-capacity-decision-comparison";
import {
  evaluateIntegrityCapacityGovernance,
  parseIntegrityCapacityGovernancePolicy,
  parseIntegrityCapacityGovernanceQuery,
  queryIntegrityCapacityGovernance,
} from "./work-integrity-remediation-capacity-governance";
import {
  buildIntegrityCapacityReviewQueue,
  parseIntegrityCapacityReviewQuery,
  queryIntegrityCapacityReviewQueue,
} from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityCapacityPortfolioReport } from "./work-integrity-remediation-capacity-portfolio";
const at = "2026-11-03T00:00:00.000Z";
const portfolio: IntegrityCapacityPortfolioReport = {
  schemaVersion: 1, captureId: "capture", evaluatedAt: at,
  policy: {
    maximumBundles: 100, maximumInterventionsPerBundle: 3,
    maximumEvaluations: 500, requireNonDegradation: true,
    minimumAssignedGain: 0, minimumCompletedGain: 0,
  },
  baseline: {
    assigned: 0, unassigned: 2, completed: 0,
    outsideHorizon: 0, completedEffortPoints: 0,
  },
  bundles: [
    {
      bundleId: "slots", interventionIds: ["slots"],
      assignedDelta: 2, completedDelta: 1,
      unassignedDelta: -2, outsideHorizonDelta: 0,
      completedEffortDelta: 3,
      newlyAssignedCandidateIds: ["one", "two"],
      lostCandidateIds: ["old"], reassignedCandidateIds: [],
      improved: true, degraded: false,
      capacity: {} as IntegrityCapacityPortfolioReport["bundles"][number]["capacity"],
      forecast: {} as IntegrityCapacityPortfolioReport["bundles"][number]["forecast"],
    },
    {
      bundleId: "points", interventionIds: ["points"],
      assignedDelta: 1, completedDelta: 2,
      unassignedDelta: -1, outsideHorizonDelta: 0,
      completedEffortDelta: 6,
      newlyAssignedCandidateIds: ["one"],
      lostCandidateIds: [], reassignedCandidateIds: [],
      improved: true, degraded: false,
      capacity: {} as IntegrityCapacityPortfolioReport["bundles"][number]["capacity"],
      forecast: {} as IntegrityCapacityPortfolioReport["bundles"][number]["forecast"],
    },
  ],
  paretoBundleIds: ["slots", "points"],
  recommendedBundleIds: ["slots", "points"],
  totals: {
    generated: 2, evaluated: 2, improved: 2,
    degraded: 0, nonDegrading: 2,
    maximumAssignedGain: 2, maximumCompletedGain: 2,
    truncated: true,
  },
  limitation: "Analytical",
};
const basePolicy = parseIntegrityCapacityDecisionPolicy(undefined);
const alternatePolicy = parseIntegrityCapacityDecisionPolicy({
  weights: {
    ASSIGNED: 1000, COMPLETED: 0, EFFORT_COMPLETED: 0,
  },
});
describe("decision policy comparison", () => {
  it("tracks selection changes and score differences", () => {
    const report = compareIntegrityCapacityDecisionPolicies(
      portfolio, basePolicy, alternatePolicy);
    expect(report.totals.selectionChanged).toBe(true);
    expect(report.before.selectedBundleId).toBe("points");
    expect(report.after.selectedBundleId).toBe("slots");
    expect(report.policyChanges.length).toBeGreaterThan(0);
  });
  it("supports filtering changed and selected bundles", () => {
    const report = compareIntegrityCapacityDecisionPolicies(
      portfolio, basePolicy, alternatePolicy);
    const page = queryIntegrityCapacityDecisionComparison(
      report, parseIntegrityCapacityDecisionComparisonQuery({
        onlySelected: true, limit: 1,
      }));
    expect(page.total).toBe(2);
    expect(page.hasMore).toBe(true);
  });
  it("rejects unknown comparison filters", () => {
    expect(() => parseIntegrityCapacityDecisionComparisonQuery({
      authorize: true,
    })).toThrow();
  });
});
describe("capacity decision governance", () => {
  const decision = decideIntegrityCapacityPortfolio(
    portfolio, alternatePolicy);
  const audit = auditIntegrityCapacityDecision(
    decision, portfolio, null, null);
  const comparison = compareIntegrityCapacityDecisionPolicies(
    portfolio, basePolicy, alternatePolicy);
  it("blocks truncated search and assignment loss", () => {
    const report = evaluateIntegrityCapacityGovernance(
      portfolio, decision, null, audit, comparison);
    expect(report.status).toBe("BLOCKED");
    expect(report.findings.map(x => x.code)).toContain(
      "TRUNCATED_PORTFOLIO");
    expect(report.findings.map(x => x.code)).toContain(
      "SELECTION_LOSES_ASSIGNED_WORK");
  });
  it("filters error findings", () => {
    const report = evaluateIntegrityCapacityGovernance(
      portfolio, decision, null, audit, comparison);
    const page = queryIntegrityCapacityGovernance(report,
      parseIntegrityCapacityGovernanceQuery({
        severities: ["ERROR"], limit: 1,
      }));
    expect(page.total).toBeGreaterThan(1);
    expect(page.hasMore).toBe(true);
  });
  it("creates prioritized human review tasks", () => {
    const report = evaluateIntegrityCapacityGovernance(
      portfolio, decision, null, audit, comparison);
    const queue = buildIntegrityCapacityReviewQueue(
      report, decision, portfolio);
    expect(queue.totals.required).toBeGreaterThan(0);
    expect(queue.tasks.some(x =>
      x.action === "VERIFY_ASSIGNMENT_IMPACT")).toBe(true);
    expect(queue.tasks.every(x => !x.canBeAutoResolved)).toBe(true);
  });
  it("filters required review tasks", () => {
    const report = evaluateIntegrityCapacityGovernance(
      portfolio, decision, null, audit, comparison);
    const queue = buildIntegrityCapacityReviewQueue(
      report, decision, portfolio);
    const page = queryIntegrityCapacityReviewQueue(queue,
      parseIntegrityCapacityReviewQuery({
        onlyRequired: true, limit: 1,
      }));
    expect(page.total).toBeGreaterThan(0);
    expect(page.tasks).toHaveLength(1);
  });
  it("rejects unknown governance policy fields", () => {
    expect(() => parseIntegrityCapacityGovernancePolicy({
      skipApprovals: true,
    })).toThrow();
  });
});
