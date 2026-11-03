import { describe, expect, it } from "vitest";
import {
  decideIntegrityCapacityPortfolio,
  parseIntegrityCapacityDecisionPolicy,
  parseIntegrityCapacityDecisionQuery,
  queryIntegrityCapacityDecision,
  auditIntegrityCapacityDecision,
} from "./work-integrity-remediation-capacity-decision";
import {
  analyzeIntegrityCapacitySensitivity,
  parseIntegrityCapacitySensitivityVariations,
  parseIntegrityCapacitySensitivityGridPolicy,
  buildIntegrityCapacitySensitivityGrid,
  parseIntegrityCapacitySensitivityQuery,
  queryIntegrityCapacitySensitivity,
} from "./work-integrity-remediation-capacity-sensitivity";
import {
  exportIntegrityCapacityDecision,
  parseIntegrityCapacityDecisionExportOptions,
} from "./work-integrity-remediation-capacity-decision-export";
import type { IntegrityCapacityPortfolioReport } from "./work-integrity-remediation-capacity-portfolio";
const at = "2026-11-03T00:00:00.000Z";
const portfolio = {
  schemaVersion: 1, captureId: "capture/one",
  evaluatedAt: at,
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
      bundleId: "=SUM(1,2)", interventionIds: ["slots"],
      assignedDelta: 2, completedDelta: 1,
      unassignedDelta: -2, outsideHorizonDelta: 0,
      completedEffortDelta: 3, newlyAssignedCandidateIds: ["one", "two"],
      lostCandidateIds: [], reassignedCandidateIds: [],
      improved: true, degraded: false,
      capacity: {} as IntegrityCapacityPortfolioReport["bundles"][number]["capacity"],
      forecast: {} as IntegrityCapacityPortfolioReport["bundles"][number]["forecast"],
    },
    {
      bundleId: "points", interventionIds: ["points"],
      assignedDelta: 1, completedDelta: 2,
      unassignedDelta: -1, outsideHorizonDelta: 0,
      completedEffortDelta: 6, newlyAssignedCandidateIds: ["one"],
      lostCandidateIds: [], reassignedCandidateIds: [],
      improved: true, degraded: false,
      capacity: {} as IntegrityCapacityPortfolioReport["bundles"][number]["capacity"],
      forecast: {} as IntegrityCapacityPortfolioReport["bundles"][number]["forecast"],
    },
    {
      bundleId: "neutral", interventionIds: ["neutral"],
      assignedDelta: 0, completedDelta: 0,
      unassignedDelta: 0, outsideHorizonDelta: 0,
      completedEffortDelta: 0, newlyAssignedCandidateIds: [],
      lostCandidateIds: [], reassignedCandidateIds: [],
      improved: false, degraded: false,
      capacity: {} as IntegrityCapacityPortfolioReport["bundles"][number]["capacity"],
      forecast: {} as IntegrityCapacityPortfolioReport["bundles"][number]["forecast"],
    },
  ],
  paretoBundleIds: ["=SUM(1,2)", "points"],
  recommendedBundleIds: ["=SUM(1,2)", "points"],
  totals: {
    generated: 3, evaluated: 3, improved: 2,
    degraded: 0, nonDegrading: 3,
    maximumAssignedGain: 2, maximumCompletedGain: 2,
    truncated: false,
  },
  limitation: "Analytical",
} satisfies IntegrityCapacityPortfolioReport;
describe("capacity decision ranking", () => {
  it("selects the highest scoring eligible option", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio);
    expect(decision.selectedBundleId).toBe("points");
    expect(decision.totals.eligible).toBe(2);
    expect(decision.excludedBundleIds).toContain("neutral");
  });
  it("changes ranking when assignment weights dominate", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio,
      parseIntegrityCapacityDecisionPolicy({
        weights: { ASSIGNED: 1000, COMPLETED: 0,
          EFFORT_COMPLETED: 0 },
      }));
    expect(decision.selectedBundleId).toBe("=SUM(1,2)");
  });
  it("rejects unknown weights and inverted score ranges", () => {
    expect(() => parseIntegrityCapacityDecisionPolicy({
      weights: { SECURITY_POSTURE: 10 },
    })).toThrow();
    expect(() => parseIntegrityCapacityDecisionQuery({
      minimumScore: 20, maximumScore: 10,
    })).toThrow();
  });
  it("filters eligible results", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio);
    const page = queryIntegrityCapacityDecision(decision,
      parseIntegrityCapacityDecisionQuery({
        onlyEligible: true, limit: 1,
      }));
    expect(page.total).toBe(2);
    expect(page.hasMore).toBe(true);
  });
  it("produces explicit audit warnings without supporting reports", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio);
    const audit = auditIntegrityCapacityDecision(
      decision, portfolio, null, null);
    expect(audit.warnings).toContain(
      "STANDALONE_INTERVENTIONS_UNAVAILABLE");
    expect(audit.completeness.attributionAvailable).toBe(false);
  });
});
describe("capacity sensitivity", () => {
  it("detects winner changes after weight variations", () => {
    const policy = parseIntegrityCapacityDecisionPolicy(undefined);
    const variations = parseIntegrityCapacitySensitivityVariations([{
      variationId: "assignment-first", axis: "ASSIGNED_WEIGHT",
      value: 1000,
    }, {
      variationId: "baseline", axis: "ASSIGNED_WEIGHT",
      value: 30,
    }]);
    const result = analyzeIntegrityCapacitySensitivity(
      portfolio, policy, variations);
    expect(result.stability.tested).toBe(2);
    expect(result.stability.changed).toBe(1);
    expect(result.observations[0]?.selectedBundleId).toBe("=SUM(1,2)");
  });
  it("builds bounded deterministic sensitivity grids", () => {
    const policy = parseIntegrityCapacityDecisionPolicy(undefined);
    const grid = parseIntegrityCapacitySensitivityGridPolicy({
      axes: ["ASSIGNED_WEIGHT"], multipliers: [0, 1, 10],
      maximumVariations: 2,
    });
    const variations = buildIntegrityCapacitySensitivityGrid(
      policy, grid);
    expect(variations).toHaveLength(2);
    expect(variations[0]?.value).toBe(0);
  });
  it("filters changed observations", () => {
    const report = analyzeIntegrityCapacitySensitivity(
      portfolio, parseIntegrityCapacityDecisionPolicy(undefined),
      parseIntegrityCapacitySensitivityVariations([{
        variationId: "assignment-first", axis: "ASSIGNED_WEIGHT",
        value: 1000,
      }]));
    const page = queryIntegrityCapacitySensitivity(report,
      parseIntegrityCapacitySensitivityQuery({ onlyChanged: true }));
    expect(page.total).toBe(1);
  });
  it("rejects duplicate variation identifiers", () => {
    expect(() => parseIntegrityCapacitySensitivityVariations([
      { variationId: "duplicate", axis: "ASSIGNED_WEIGHT", value: 1 },
      { variationId: "duplicate", axis: "COMPLETED_WEIGHT", value: 1 },
    ])).toThrow();
  });
});
describe("capacity decision export", () => {
  it("neutralizes spreadsheet formula prefixes", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio);
    const exported = exportIntegrityCapacityDecision(
      decision, null, null,
      parseIntegrityCapacityDecisionExportOptions({
        format: "CSV", sections: ["DECISIONS"],
      }));
    expect(exported.content).toContain("'=SUM(1,2)");
    expect(exported.fileName).toBe(
      "integrity-capacity-decision-capture_one.csv");
  });
  it("exports structured JSONL and truncation metadata", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio);
    const exported = exportIntegrityCapacityDecision(
      decision, null, null,
      parseIntegrityCapacityDecisionExportOptions({
        format: "JSONL", maximumRows: 2,
      }));
    expect(exported.truncated).toBe(true);
    expect(exported.content.split("\n").filter(Boolean)).toHaveLength(3);
  });
  it("requires a sensitivity report for sensitivity export", () => {
    const decision = decideIntegrityCapacityPortfolio(portfolio);
    expect(() => exportIntegrityCapacityDecision(
      decision, null, null,
      parseIntegrityCapacityDecisionExportOptions({
        sections: ["SENSITIVITY"],
      }))).toThrow();
  });
});
