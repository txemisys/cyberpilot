import { describe, expect, it } from "vitest";
import {
  attributeIntegrityCapacityInterventions,
  parseIntegrityCapacityInterventionAttributionQuery,
  queryIntegrityCapacityInterventionAttribution,
} from "./work-integrity-remediation-capacity-attribution";
import type {
  IntegrityCapacityInterventionReport,
} from "./work-integrity-remediation-capacity-interventions";
import type {
  IntegrityCapacityPortfolioReport,
  IntegrityCapacityPortfolioBundle,
} from "./work-integrity-remediation-capacity-portfolio";
const capacity = {
  schemaVersion: 1 as const,
  captureId: "capture",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  policy: {
    maximumAssignments: 10, maximumCandidatesPerCase: 10,
    defaultEffortPoints: 3, effortByAction: {},
    effortByStep: {}, enforceDistinctWorkItems: true,
    prioritizeUnassigned: false, allowReadyCandidates: false,
  },
  assignments: [], unassigned: [], members: [],
  limitation: "Analytical",
  totals: {
    queued: 0, assigned: 0, existing: 0,
    proposed: 0, unassigned: 0, totalEffortPoints: 0,
    assignedEffortPoints: 0, unassignedEffortPoints: 0,
    availablePoints: 0, remainingPoints: 0,
    availableSlots: 0, remainingSlots: 0,
    assignmentPercent: 100,
    byUnassignedReason: {
      READY: 0, QUEUE_LIMIT: 0, NO_CAPABLE_MEMBER: 0,
      CAPACITY_EXHAUSTED: 0, CASE_LIMIT: 0,
      DUPLICATE_WORK_ITEM: 0,
      CONFLICTING_EXISTING_ASSIGNMENT: 0,
    },
  },
};
const forecast = {
  schemaVersion: 1 as const,
  captureId: "capture",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  policy: {
    workingDaysPerWeek: 5, pointsPerDay: 3,
    maximumForecastDays: 90, includeUnassigned: true,
    includeExisting: true, includeProposed: true,
  },
  tasks: [], days: [], actors: [],
  limitation: "Analytical",
  totals: {
    candidates: 0, scheduled: 0, outsideHorizon: 0,
    unavailable: 0, completedWithinHorizon: 0,
    scheduledPoints: 0, completedPoints: 0,
    remainingPoints: 0, calendarDays: 0,
    workingDays: 0, lastScheduledDate: null,
  },
};
function bundle(
  bundleId: string, interventionIds: string[],
  assignedDelta: number, completedDelta: number,
): IntegrityCapacityPortfolioBundle {
  return {
    bundleId, interventionIds, assignedDelta, completedDelta,
    unassignedDelta: -assignedDelta,
    outsideHorizonDelta: -completedDelta,
    completedEffortDelta: completedDelta * 3,
    newlyAssignedCandidateIds: [], lostCandidateIds: [],
    reassignedCandidateIds: [],
    improved: assignedDelta > 0 || completedDelta > 0,
    degraded: false, capacity, forecast,
  };
}
const outcomes: IntegrityCapacityInterventionReport = {
  schemaVersion: 1, captureId: "capture",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  baseline: {
    assigned: 0, completedWithinHorizon: 0,
    unassigned: 0, outsideHorizon: 0,
    completedEffortPoints: 0,
  },
  outcomes: [
    {
      interventionId: "slots", kind: "INCREASE_SLOTS",
      assignedDelta: 1, completedDelta: 1,
      unassignedDelta: -1, outsideHorizonDelta: -1,
      effortCompletedDelta: 3,
      gainedCandidateIds: [], lostCandidateIds: [],
      reassignedCandidateIds: [], improved: true,
      degraded: false, neutral: false, capacity, forecast,
    },
    {
      interventionId: "points", kind: "INCREASE_POINTS",
      assignedDelta: 0, completedDelta: 0,
      unassignedDelta: 0, outsideHorizonDelta: 0,
      effortCompletedDelta: 0,
      gainedCandidateIds: [], lostCandidateIds: [],
      reassignedCandidateIds: [], improved: false,
      degraded: false, neutral: true, capacity, forecast,
    },
  ],
  recommendedInterventionIds: ["slots"],
  totals: {
    evaluated: 2, improved: 1, degraded: 0, neutral: 1,
    maximumAssignedGain: 1, maximumCompletionGain: 1,
    maximumCompletedEffortGain: 3,
  },
  limitation: "Analytical",
};
const bundles = [
  bundle("slots", ["slots"], 1, 1),
  bundle("points", ["points"], 0, 0),
  bundle("points+slots", ["points", "slots"], 2, 2),
];
const portfolio: IntegrityCapacityPortfolioReport = {
  schemaVersion: 1, captureId: "capture",
  evaluatedAt: "2026-11-03T00:00:00.000Z",
  policy: {
    maximumBundles: 100, maximumInterventionsPerBundle: 3,
    maximumEvaluations: 500, requireNonDegradation: true,
    minimumAssignedGain: 0, minimumCompletedGain: 0,
  },
  baseline: {
    assigned: 0, unassigned: 0, completed: 0,
    outsideHorizon: 0, completedEffortPoints: 0,
  },
  bundles, paretoBundleIds: ["points+slots"],
  recommendedBundleIds: ["points+slots"],
  totals: {
    generated: 3, evaluated: 3, improved: 2,
    degraded: 0, nonDegrading: 3,
    maximumAssignedGain: 2, maximumCompletedGain: 2,
    truncated: false,
  },
  limitation: "Analytical",
};
describe("capacity attribution", () => {
  it("detects positive pairwise interaction", () => {
    const report = attributeIntegrityCapacityInterventions(
      outcomes, portfolio);
    expect(report.totals.withPositiveSynergy).toBe(2);
    expect(report.interventions.find(x =>
      x.interventionId === "slots")?.interactions[0]?.completionSynergy).toBe(1);
  });
  it("computes marginal gain against other intervention", () => {
    const report = attributeIntegrityCapacityInterventions(
      outcomes, portfolio);
    expect(report.interventions.find(x =>
      x.interventionId === "points")?.marginalCompletionGain).toBe(1);
  });
  it("queries positive synergy", () => {
    const report = attributeIntegrityCapacityInterventions(
      outcomes, portfolio);
    const page = queryIntegrityCapacityInterventionAttribution(report,
      parseIntegrityCapacityInterventionAttributionQuery({
        onlyPositiveSynergy: true, limit: 1,
      }));
    expect(page.total).toBe(2);
    expect(page.hasMore).toBe(true);
  });
  it("rejects mismatched capture", () => {
    expect(() => attributeIntegrityCapacityInterventions(
      outcomes, { ...portfolio, captureId: "other" })).toThrow();
  });
  it("rejects unknown query fields", () => {
    expect(() => parseIntegrityCapacityInterventionAttributionQuery({
      mutateAssignments: true,
    })).toThrow();
  });
});
