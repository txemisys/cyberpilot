import { WorkInputError } from "./remediation-work-input";
import {
  decideIntegrityCapacityPortfolio,
  parseIntegrityCapacityDecisionPolicy,
  type IntegrityCapacityDecisionPolicy,
  type IntegrityCapacityDecisionReport,
} from "./work-integrity-remediation-capacity-decision";
import type {
  IntegrityCapacityPortfolioReport,
} from "./work-integrity-remediation-capacity-portfolio";

export type IntegrityCapacitySensitivityAxis =
  | "COMPLETED_WEIGHT" | "ASSIGNED_WEIGHT" | "EFFORT_WEIGHT"
  | "OUTSIDE_HORIZON_WEIGHT" | "UNASSIGNED_WEIGHT"
  | "INTERVENTION_COST_WEIGHT" | "MINIMUM_COMPLETED_GAIN"
  | "MINIMUM_ASSIGNED_GAIN" | "MAXIMUM_INTERVENTIONS";
export type IntegrityCapacitySensitivityVariation = {
  variationId: string;
  axis: IntegrityCapacitySensitivityAxis;
  value: number;
};
export type IntegrityCapacitySensitivityObservation = {
  variationId: string;
  axis: IntegrityCapacitySensitivityAxis;
  value: number;
  selectedBundleId: string | null;
  selectedScore: number | null;
  eligible: number;
  excluded: number;
  selectionChanged: boolean;
  scoreDelta: number | null;
  selectedCompletedGain: number | null;
  selectedAssignedGain: number | null;
  selectedInterventionCount: number | null;
  topThreeBundleIds: string[];
  selectionReason: string;
};
export type IntegrityCapacitySensitivityReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  baseline: {
    selectedBundleId: string | null;
    selectedScore: number | null;
    eligible: number;
    excluded: number;
  };
  observations: IntegrityCapacitySensitivityObservation[];
  stability: {
    tested: number;
    unchanged: number;
    changed: number;
    withoutSelection: number;
    selectionStabilityPercent: number;
    distinctWinningBundleIds: string[];
    winnerFrequency: Record<string, number>;
    mostFrequentWinnerId: string | null;
    mostSensitiveAxes: Array<{
      axis: IntegrityCapacitySensitivityAxis;
      tested: number;
      changed: number;
      changePercent: number;
    }>;
  };
  limitation: string;
};
export type IntegrityCapacitySensitivityQuery = {
  axes?: IntegrityCapacitySensitivityAxis[];
  onlyChanged?: boolean;
  selectedBundleIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityCapacitySensitivityPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  observations: IntegrityCapacitySensitivityObservation[];
};
const axes: IntegrityCapacitySensitivityAxis[] = [
  "COMPLETED_WEIGHT", "ASSIGNED_WEIGHT", "EFFORT_WEIGHT",
  "OUTSIDE_HORIZON_WEIGHT", "UNASSIGNED_WEIGHT",
  "INTERVENTION_COST_WEIGHT", "MINIMUM_COMPLETED_GAIN",
  "MINIMUM_ASSIGNED_GAIN", "MAXIMUM_INTERVENTIONS",
];
const weightAxes: Record<string, keyof IntegrityCapacityDecisionPolicy["weights"]> = {
  COMPLETED_WEIGHT: "COMPLETED",
  ASSIGNED_WEIGHT: "ASSIGNED",
  EFFORT_WEIGHT: "EFFORT_COMPLETED",
  OUTSIDE_HORIZON_WEIGHT: "OUTSIDE_HORIZON",
  UNASSIGNED_WEIGHT: "UNASSIGNED",
  INTERVENTION_COST_WEIGHT: "INTERVENTION_COUNT",
};
function object(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function number(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isFinite(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function integer(value: unknown, label: string, min: number, max: number) {
  const parsed = number(value, label, min, max);
  if (!Number.isSafeInteger(parsed))
    throw new WorkInputError("INVALID", "Invalid integer " + label);
  return parsed;
}
function identifiers(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
export function parseIntegrityCapacitySensitivityVariations(
  value: unknown,
): IntegrityCapacitySensitivityVariation[] {
  if (!Array.isArray(value) || !value.length || value.length > 100)
    throw new WorkInputError("INVALID", "Invalid sensitivity variations.");
  const parsed = value.map(item => {
    const raw = object(item, "sensitivity variation");
    if (Object.keys(raw).some(x =>
      !["variationId", "axis", "value"].includes(x)))
      throw new WorkInputError("INVALID", "Unknown variation field.");
    if (typeof raw.variationId !== "string" || !raw.variationId ||
        raw.variationId.length > 150 ||
        /[\u0000-\u001f\u007f]/.test(raw.variationId))
      throw new WorkInputError("INVALID", "Invalid variation ID.");
    if (!axes.includes(raw.axis as IntegrityCapacitySensitivityAxis))
      throw new WorkInputError("INVALID", "Unknown sensitivity axis.");
    const axis = raw.axis as IntegrityCapacitySensitivityAxis;
    const numeric = axis === "MAXIMUM_INTERVENTIONS" ?
      integer(raw.value, "intervention limit", 1, 5) :
      axis.endsWith("_WEIGHT") ?
        number(raw.value, "sensitivity weight", 0, 10000) :
        integer(raw.value, "sensitivity threshold", 0, 10000);
    return {
      variationId: raw.variationId as string,
      axis, value: numeric,
    };
  });
  if (new Set(parsed.map(x => x.variationId)).size !== parsed.length)
    throw new WorkInputError("INVALID", "Duplicate sensitivity variation ID.");
  return parsed;
}
function vary(
  baseline: IntegrityCapacityDecisionPolicy,
  variation: IntegrityCapacitySensitivityVariation,
): IntegrityCapacityDecisionPolicy {
  const weights = { ...baseline.weights };
  const policy = { ...baseline, weights };
  const weight = weightAxes[variation.axis];
  if (weight) {
    weights[weight] = variation.value;
  } else if (variation.axis === "MINIMUM_COMPLETED_GAIN") {
    policy.minimumCompletedGain = variation.value;
  } else if (variation.axis === "MINIMUM_ASSIGNED_GAIN") {
    policy.minimumAssignedGain = variation.value;
  } else if (variation.axis === "MAXIMUM_INTERVENTIONS") {
    policy.maximumInterventions = variation.value;
  } else {
    throw new WorkInputError("INVALID", "Unsupported sensitivity axis.");
  }
  return policy;
}
function selectionReason(
  report: IntegrityCapacityDecisionReport,
): string {
  if (report.selectedBundleId === null) {
    const reasons = Object.entries(report.totals.byExclusionReason)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return reasons[0] ?
      "No eligible bundles; most common exclusion: " + reasons[0][0] :
      "No eligible bundles in evaluated portfolio.";
  }
  const winner = report.candidates.find(x =>
    x.bundleId === report.selectedBundleId);
  if (!winner) return "Selected bundle not present in candidate list.";
  return "Highest ranked eligible bundle with " +
    winner.completedGain + " completion gain, " +
    winner.assignedGain + " assignment gain, and " +
    winner.interventionCount + " interventions.";
}
export function analyzeIntegrityCapacitySensitivity(
  portfolio: IntegrityCapacityPortfolioReport,
  baselinePolicy: IntegrityCapacityDecisionPolicy,
  variations: readonly IntegrityCapacitySensitivityVariation[],
): IntegrityCapacitySensitivityReport {
  if (!variations.length || variations.length > 100 ||
      new Set(variations.map(x => x.variationId)).size !== variations.length)
    throw new WorkInputError("INVALID", "Invalid sensitivity variations.");
  const baseline = decideIntegrityCapacityPortfolio(portfolio, baselinePolicy);
  const observations = variations.map(variation => {
    const report = decideIntegrityCapacityPortfolio(
      portfolio, vary(baselinePolicy, variation));
    const winner = report.candidates.find(x =>
      x.bundleId === report.selectedBundleId);
    return {
      variationId: variation.variationId,
      axis: variation.axis,
      value: variation.value,
      selectedBundleId: report.selectedBundleId,
      selectedScore: report.totals.selectedScore,
      eligible: report.totals.eligible,
      excluded: report.totals.excluded,
      selectionChanged: report.selectedBundleId !==
        baseline.selectedBundleId,
      scoreDelta: report.totals.selectedScore === null ||
        baseline.totals.selectedScore === null ? null :
        Math.round(100 * (report.totals.selectedScore -
          baseline.totals.selectedScore)) / 100,
      selectedCompletedGain: winner?.completedGain ?? null,
      selectedAssignedGain: winner?.assignedGain ?? null,
      selectedInterventionCount: winner?.interventionCount ?? null,
      topThreeBundleIds: report.candidates.filter(x =>
        x.eligible).slice(0, 3).map(x => x.bundleId),
      selectionReason: selectionReason(report),
    };
  });
  const winnerFrequency: Record<string, number> = {};
  for (const observation of observations) {
    if (observation.selectedBundleId === null) continue;
    const key = observation.selectedBundleId;
    winnerFrequency[key] = (winnerFrequency[key] ?? 0) + 1;
  }
  const winners = Object.entries(winnerFrequency).sort((a, b) =>
    b[1] - a[1] || a[0].localeCompare(b[0]));
  const mostSensitiveAxes = axes.map(axis => {
    const selected = observations.filter(x => x.axis === axis);
    const changed = selected.filter(x => x.selectionChanged).length;
    return {
      axis, tested: selected.length, changed,
      changePercent: selected.length ?
        Math.round(100 * changed / selected.length) : 0,
    };
  }).filter(x => x.tested).sort((a, b) =>
    b.changePercent - a.changePercent ||
    b.changed - a.changed || a.axis.localeCompare(b.axis));
  const unchanged = observations.filter(x =>
    !x.selectionChanged).length;
  return {
    schemaVersion: 1, captureId: portfolio.captureId,
    evaluatedAt: portfolio.evaluatedAt,
    baseline: {
      selectedBundleId: baseline.selectedBundleId,
      selectedScore: baseline.totals.selectedScore,
      eligible: baseline.totals.eligible,
      excluded: baseline.totals.excluded,
    },
    observations,
    stability: {
      tested: observations.length,
      unchanged, changed: observations.length - unchanged,
      withoutSelection: observations.filter(x =>
        x.selectedBundleId === null).length,
      selectionStabilityPercent: Math.round(100 *
        unchanged / observations.length),
      distinctWinningBundleIds: winners.map(x => x[0]),
      winnerFrequency,
      mostFrequentWinnerId: winners[0]?.[0] ?? null,
      mostSensitiveAxes,
    },
    limitation: "One parameter changes per variation. Stability describes the evaluated model, not future performance or evidence of real-world effectiveness.",
  };
}
export function parseIntegrityCapacitySensitivityQuery(
  value: unknown,
): IntegrityCapacitySensitivityQuery {
  const raw = object(value, "sensitivity query");
  if (Object.keys(raw).some(x => ![
    "axes", "onlyChanged", "selectedBundleIds", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown sensitivity query field.");
  const selectedAxes = raw.axes === undefined ? undefined :
    identifiers(raw.axes, "sensitivity axes", axes.length);
  if (selectedAxes?.some(x => !axes.includes(
    x as IntegrityCapacitySensitivityAxis)))
    throw new WorkInputError("INVALID", "Unknown sensitivity axis filter.");
  if (raw.onlyChanged !== undefined &&
      typeof raw.onlyChanged !== "boolean")
    throw new WorkInputError("INVALID", "Invalid sensitivity filter.");
  return {
    ...(selectedAxes === undefined ? {} : {
      axes: selectedAxes as IntegrityCapacitySensitivityAxis[],
    }),
    ...(raw.selectedBundleIds === undefined ? {} : {
      selectedBundleIds: identifiers(raw.selectedBundleIds,
        "sensitivity selected bundle IDs", 500),
    }),
    onlyChanged: raw.onlyChanged === true,
    offset: integer(raw.offset ?? 0, "sensitivity offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "sensitivity limit", 1, 500),
  };
}
export function queryIntegrityCapacitySensitivity(
  report: IntegrityCapacitySensitivityReport,
  query: IntegrityCapacitySensitivityQuery,
): IntegrityCapacitySensitivityPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const observations = report.observations.filter(x =>
    (!query.axes || query.axes.includes(x.axis)) &&
    (!query.onlyChanged || x.selectionChanged) &&
    (!query.selectedBundleIds ||
      (x.selectedBundleId !== null &&
        query.selectedBundleIds.includes(x.selectedBundleId))));
  return {
    captureId: report.captureId,
    total: observations.length,
    offset, limit,
    hasMore: offset + limit < observations.length,
    observations: observations.slice(offset, offset + limit),
  };
}
export type IntegrityCapacitySensitivityGridPolicy = {
  axes: IntegrityCapacitySensitivityAxis[];
  multipliers: number[];
  maximumVariations: number;
};
export function buildIntegrityCapacitySensitivityGrid(
  baselinePolicy: IntegrityCapacityDecisionPolicy,
  grid: IntegrityCapacitySensitivityGridPolicy,
): IntegrityCapacitySensitivityVariation[] {
  if (!Array.isArray(grid.axes) || !grid.axes.length ||
      grid.axes.length > axes.length ||
      grid.axes.some(x => !axes.includes(x)) ||
      new Set(grid.axes).size !== grid.axes.length)
    throw new WorkInputError("INVALID", "Invalid sensitivity grid axes.");
  if (!Array.isArray(grid.multipliers) || !grid.multipliers.length ||
      grid.multipliers.length > 20 ||
      grid.multipliers.some(x => typeof x !== "number" ||
        !Number.isFinite(x) || x < 0 || x > 100))
    throw new WorkInputError("INVALID", "Invalid sensitivity multipliers.");
  const maximum = integer(grid.maximumVariations,
    "grid variation limit", 1, 100);
  const variations: IntegrityCapacitySensitivityVariation[] = [];
  for (const axis of grid.axes) {
    const weight = weightAxes[axis];
    const original = weight ? baselinePolicy.weights[weight] :
      axis === "MINIMUM_COMPLETED_GAIN" ?
        baselinePolicy.minimumCompletedGain :
      axis === "MINIMUM_ASSIGNED_GAIN" ?
        baselinePolicy.minimumAssignedGain :
        baselinePolicy.maximumInterventions;
    for (const multiplier of grid.multipliers) {
      const value = axis.endsWith("_WEIGHT") ?
        Math.round(100 * original * multiplier) / 100 :
        Math.round(original * multiplier);
      const capped = axis === "MAXIMUM_INTERVENTIONS" ?
        Math.max(1, Math.min(5, value)) :
        Math.max(0, Math.min(10000, value));
      if (variations.length >= maximum) return variations;
      variations.push({
        variationId: axis + ":" + multiplier.toString(),
        axis, value: capped,
      });
    }
  }
  return parseIntegrityCapacitySensitivityVariations(variations);
}
export function parseIntegrityCapacitySensitivityGridPolicy(
  value: unknown,
): IntegrityCapacitySensitivityGridPolicy {
  const raw = object(value, "sensitivity grid");
  if (Object.keys(raw).some(x =>
    !["axes", "multipliers", "maximumVariations"].includes(x)))
    throw new WorkInputError("INVALID", "Unknown sensitivity grid field.");
  const selected = identifiers(raw.axes, "sensitivity axes", axes.length);
  if (!selected.length || selected.some(x => !axes.includes(
    x as IntegrityCapacitySensitivityAxis)))
    throw new WorkInputError("INVALID", "Invalid sensitivity axes.");
  if (!Array.isArray(raw.multipliers) || !raw.multipliers.length ||
      raw.multipliers.length > 20)
    throw new WorkInputError("INVALID", "Invalid sensitivity multipliers.");
  const multipliers = raw.multipliers.map(x =>
    number(x, "sensitivity multiplier", 0, 100));
  return {
    axes: selected as IntegrityCapacitySensitivityAxis[],
    multipliers,
    maximumVariations: integer(raw.maximumVariations ?? 100,
      "maximum variations", 1, 100),
  };
}
export function evaluateIntegrityCapacitySensitivityGrid(
  portfolio: IntegrityCapacityPortfolioReport,
  policy: IntegrityCapacityDecisionPolicy,
  grid: IntegrityCapacitySensitivityGridPolicy,
): IntegrityCapacitySensitivityReport {
  return analyzeIntegrityCapacitySensitivity(
    portfolio, policy, buildIntegrityCapacitySensitivityGrid(policy, grid));
}
