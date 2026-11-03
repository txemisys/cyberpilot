import { WorkInputError } from "./remediation-work-input";
import {
  planIntegrityExecutionCapacity,
  type IntegrityExecutionCapacityMember,
  type IntegrityExecutionCapacityPlan,
  type IntegrityExecutionCapacityPolicy,
} from "./work-integrity-remediation-execution-capacity";
import {
  forecastIntegrityExecutionCapacity,
  type IntegrityExecutionCapacityForecast,
  type IntegrityExecutionCapacityForecastPolicy,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";
import {
  parseIntegrityCapacityInterventions,
  type IntegrityCapacityIntervention,
} from "./work-integrity-remediation-capacity-interventions";

export type IntegrityCapacityPortfolioPolicy = {
  maximumBundles: number;
  maximumInterventionsPerBundle: number;
  maximumEvaluations: number;
  requireNonDegradation: boolean;
  minimumAssignedGain: number;
  minimumCompletedGain: number;
};
export type IntegrityCapacityPortfolioBundle = {
  bundleId: string;
  interventionIds: string[];
  assignedDelta: number;
  completedDelta: number;
  unassignedDelta: number;
  outsideHorizonDelta: number;
  completedEffortDelta: number;
  newlyAssignedCandidateIds: string[];
  lostCandidateIds: string[];
  reassignedCandidateIds: string[];
  improved: boolean;
  degraded: boolean;
  capacity: IntegrityExecutionCapacityPlan;
  forecast: IntegrityExecutionCapacityForecast;
};
export type IntegrityCapacityPortfolioReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityCapacityPortfolioPolicy;
  baseline: {
    assigned: number;
    unassigned: number;
    completed: number;
    outsideHorizon: number;
    completedEffortPoints: number;
  };
  bundles: IntegrityCapacityPortfolioBundle[];
  paretoBundleIds: string[];
  recommendedBundleIds: string[];
  totals: {
    generated: number;
    evaluated: number;
    improved: number;
    degraded: number;
    nonDegrading: number;
    maximumAssignedGain: number;
    maximumCompletedGain: number;
    truncated: boolean;
  };
  limitation: string;
};
export type IntegrityCapacityPortfolioQuery = {
  bundleIds?: string[];
  interventionIds?: string[];
  onlyPareto?: boolean;
  onlyNonDegrading?: boolean;
  minimumAssignedGain?: number;
  minimumCompletedGain?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityPortfolioPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  bundles: IntegrityCapacityPortfolioBundle[];
};
const defaults: IntegrityCapacityPortfolioPolicy = {
  maximumBundles: 100,
  maximumInterventionsPerBundle: 3,
  maximumEvaluations: 500,
  requireNonDegradation: true,
  minimumAssignedGain: 0,
  minimumCompletedGain: 0,
};
function object(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
export function parseIntegrityCapacityPortfolioPolicy(
  value: unknown,
): IntegrityCapacityPortfolioPolicy {
  if (value === undefined) return { ...defaults };
  const raw = object(value, "portfolio policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown portfolio policy field.");
  const result = { ...defaults };
  for (const key of [
    "maximumBundles", "maximumInterventionsPerBundle",
    "maximumEvaluations", "minimumAssignedGain", "minimumCompletedGain",
  ] as const) {
    if (raw[key] !== undefined)
      result[key] = integer(raw[key], key,
        key.startsWith("minimum") ? 0 : 1,
        key === "maximumInterventionsPerBundle" ? 5 :
        key === "maximumEvaluations" ? 1000 :
        key === "maximumBundles" ? 500 : 10000);
  }
  if (raw.requireNonDegradation !== undefined) {
    if (typeof raw.requireNonDegradation !== "boolean")
      throw new WorkInputError("INVALID", "Invalid portfolio degradation flag.");
    result.requireNonDegradation = raw.requireNonDegradation;
  }
  return result;
}
function apply(
  members: IntegrityExecutionCapacityMember[],
  capacityPolicy: IntegrityExecutionCapacityPolicy,
  forecastPolicy: IntegrityExecutionCapacityForecastPolicy,
  intervention: IntegrityCapacityIntervention,
) {
  const updated = members.map(x => ({
    ...x,
    supportedActions: [...x.supportedActions],
    supportedSteps: [...x.supportedSteps],
    excludedCaseKeys: [...x.excludedCaseKeys],
    assignedCandidateIds: [...x.assignedCandidateIds],
  }));
  const capacity = { ...capacityPolicy };
  const forecast = { ...forecastPolicy };
  if (intervention.kind === "ADD_MEMBER") {
    if (updated.some(x => x.actorUserId === intervention.member.actorUserId))
      throw new WorkInputError("INVALID", "Duplicate added portfolio actor.");
    updated.push({ ...intervention.member });
  } else if (intervention.kind === "INCREASE_CASE_LIMIT") {
    capacity.maximumCandidatesPerCase = integer(
      capacity.maximumCandidatesPerCase + intervention.additionalLimit,
      "resulting case limit", 1, 10000);
  } else if (intervention.kind === "INCREASE_FORECAST_DAYS") {
    forecast.maximumForecastDays = integer(
      forecast.maximumForecastDays + intervention.additionalDays,
      "resulting forecast horizon", 1, 365);
  } else if (intervention.kind === "INCREASE_DAILY_THROUGHPUT") {
    forecast.pointsPerDay = integer(
      forecast.pointsPerDay + intervention.additionalPoints,
      "resulting daily points", 1, 10000);
  } else {
    const index = updated.findIndex(x =>
      x.actorUserId === intervention.actorUserId);
    if (index < 0)
      throw new WorkInputError("INVALID", "Unknown portfolio actor.");
    const member = updated[index]!;
    if (intervention.kind === "REMOVE_MEMBER") {
      if (member.assignedCandidateIds.length)
        throw new WorkInputError("INVALID", "Cannot remove assigned actor.");
      updated.splice(index, 1);
    } else if (intervention.kind === "INCREASE_SLOTS") {
      member.maximumConcurrent = integer(
        member.maximumConcurrent + intervention.additionalSlots,
        "resulting slots", 0, 10000);
    } else if (intervention.kind === "INCREASE_POINTS") {
      member.maximumPoints = integer(
        member.maximumPoints + intervention.additionalPoints,
        "resulting points", 0, 1000000);
    } else if (intervention.kind === "ENABLE_ACTION") {
      member.supportedActions = [...new Set([
        ...member.supportedActions, intervention.action,
      ])];
    } else if (intervention.kind === "ENABLE_STEP") {
      member.supportedSteps = [...new Set([
        ...member.supportedSteps, intervention.step,
      ])];
    } else if (intervention.kind === "UNBLOCK_CASE") {
      member.excludedCaseKeys = member.excludedCaseKeys.filter(x =>
        x !== intervention.caseKey);
    }
  }
  return { members: updated, capacityPolicy: capacity, forecastPolicy: forecast };
}
function dominance(
  a: IntegrityCapacityPortfolioBundle,
  b: IntegrityCapacityPortfolioBundle,
) {
  return a.assignedDelta >= b.assignedDelta &&
    a.completedDelta >= b.completedDelta &&
    a.unassignedDelta <= b.unassignedDelta &&
    a.outsideHorizonDelta <= b.outsideHorizonDelta &&
    (a.assignedDelta > b.assignedDelta ||
      a.completedDelta > b.completedDelta ||
      a.unassignedDelta < b.unassignedDelta ||
      a.outsideHorizonDelta < b.outsideHorizonDelta);
}
export function evaluateIntegrityCapacityPortfolio(
  queue: IntegrityExecutionRemediationQueue,
  members: readonly IntegrityExecutionCapacityMember[],
  evaluatedAt: string,
  capacityPolicy: IntegrityExecutionCapacityPolicy,
  forecastPolicy: IntegrityExecutionCapacityForecastPolicy,
  interventions: readonly IntegrityCapacityIntervention[],
  policy: IntegrityCapacityPortfolioPolicy = defaults,
): IntegrityCapacityPortfolioReport {
  if (!interventions.length || interventions.length > 50 ||
      new Set(interventions.map(x => x.interventionId)).size !== interventions.length)
    throw new WorkInputError("INVALID", "Invalid portfolio interventions.");
  const baselineCapacity = planIntegrityExecutionCapacity(
    queue, members, evaluatedAt, capacityPolicy);
  const baselineForecast = forecastIntegrityExecutionCapacity(
    baselineCapacity, queue, evaluatedAt, forecastPolicy);
  const ordered = [...interventions].sort((a, b) =>
    a.interventionId.localeCompare(b.interventionId));
  const bundles: IntegrityCapacityPortfolioBundle[] = [];
  let generated = 0;
  let truncated = false;
  const evaluate = (selection: IntegrityCapacityIntervention[]) => {
    generated++;
    if (generated > policy.maximumEvaluations) {
      truncated = true;
      return;
    }
    try {
      let state = {
        members: members.map(x => ({ ...x })),
        capacityPolicy: { ...capacityPolicy },
        forecastPolicy: { ...forecastPolicy },
      };
      for (const intervention of selection)
        state = apply(state.members, state.capacityPolicy,
          state.forecastPolicy, intervention);
      const capacity = planIntegrityExecutionCapacity(
        queue, state.members, evaluatedAt, state.capacityPolicy);
      const forecast = forecastIntegrityExecutionCapacity(
        capacity, queue, evaluatedAt, state.forecastPolicy);
      const before = new Map(baselineCapacity.assignments.map(x =>
        [x.candidateId, x.actorUserId]));
      const after = new Map(capacity.assignments.map(x =>
        [x.candidateId, x.actorUserId]));
      const assignedDelta = capacity.totals.assigned -
        baselineCapacity.totals.assigned;
      const completedDelta = forecast.totals.completedWithinHorizon -
        baselineForecast.totals.completedWithinHorizon;
      const unassignedDelta = capacity.totals.unassigned -
        baselineCapacity.totals.unassigned;
      const outsideHorizonDelta = forecast.totals.outsideHorizon -
        baselineForecast.totals.outsideHorizon;
      const completedEffortDelta = forecast.totals.completedPoints -
        baselineForecast.totals.completedPoints;
      const improved = assignedDelta > 0 || completedDelta > 0 ||
        unassignedDelta < 0 || outsideHorizonDelta < 0 ||
        completedEffortDelta > 0;
      const degraded = assignedDelta < 0 || completedDelta < 0 ||
        unassignedDelta > 0 || outsideHorizonDelta > 0 ||
        completedEffortDelta < 0;
      bundles.push({
        bundleId: selection.map(x => x.interventionId).join("+"),
        interventionIds: selection.map(x => x.interventionId),
        assignedDelta, completedDelta, unassignedDelta,
        outsideHorizonDelta, completedEffortDelta,
        newlyAssignedCandidateIds: [...after.keys()].filter(x =>
          !before.has(x)).sort(),
        lostCandidateIds: [...before.keys()].filter(x =>
          !after.has(x)).sort(),
        reassignedCandidateIds: [...after].filter(([id, actor]) =>
          before.has(id) && before.get(id) !== actor)
          .map(([id]) => id).sort(),
        improved, degraded, capacity, forecast,
      });
    } catch (error) {
      if (!(error instanceof WorkInputError)) throw error;
    }
  };
  const enumerate = (start: number, selection: IntegrityCapacityIntervention[]) => {
    if (generated >= policy.maximumEvaluations) {
      truncated = true;
      return;
    }
    if (selection.length) evaluate(selection);
    if (selection.length >= policy.maximumInterventionsPerBundle) return;
    for (let index = start; index < ordered.length; index++) {
      if (generated >= policy.maximumEvaluations) {
        truncated = true;
        break;
      }
      enumerate(index + 1, [...selection, ordered[index]!]);
    }
  };
  enumerate(0, []);
  bundles.sort((a, b) =>
    b.completedDelta - a.completedDelta ||
    b.assignedDelta - a.assignedDelta ||
    b.completedEffortDelta - a.completedEffortDelta ||
    a.interventionIds.length - b.interventionIds.length ||
    a.bundleId.localeCompare(b.bundleId));
  const selected = bundles.slice(0, policy.maximumBundles);
  if (bundles.length > selected.length) truncated = true;
  const paretoBundleIds = selected.filter(x =>
    !selected.some(y => y.bundleId !== x.bundleId &&
      dominance(y, x))).map(x => x.bundleId);
  const recommendedBundleIds = selected.filter(x =>
    x.improved && (!policy.requireNonDegradation || !x.degraded) &&
    x.assignedDelta >= policy.minimumAssignedGain &&
    x.completedDelta >= policy.minimumCompletedGain)
    .map(x => x.bundleId);
  return {
    schemaVersion: 1, captureId: queue.captureId, evaluatedAt,
    policy, baseline: {
      assigned: baselineCapacity.totals.assigned,
      unassigned: baselineCapacity.totals.unassigned,
      completed: baselineForecast.totals.completedWithinHorizon,
      outsideHorizon: baselineForecast.totals.outsideHorizon,
      completedEffortPoints: baselineForecast.totals.completedPoints,
    },
    bundles: selected, paretoBundleIds, recommendedBundleIds,
    totals: {
      generated, evaluated: selected.length,
      improved: selected.filter(x => x.improved).length,
      degraded: selected.filter(x => x.degraded).length,
      nonDegrading: selected.filter(x => !x.degraded).length,
      maximumAssignedGain: Math.max(0, ...selected.map(x => x.assignedDelta)),
      maximumCompletedGain: Math.max(0, ...selected.map(x => x.completedDelta)),
      truncated,
    },
    limitation: "Portfolio combinations are bounded what-if simulations, not approved staffing or operational actions. Invalid combinations are omitted and results may be truncated.",
  };
}
export function parseIntegrityCapacityPortfolioQuery(
  value: unknown,
): IntegrityCapacityPortfolioQuery {
  const raw = object(value, "portfolio query");
  if (Object.keys(raw).some(x => ![
    "bundleIds", "interventionIds", "onlyPareto",
    "onlyNonDegrading", "minimumAssignedGain",
    "minimumCompletedGain", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown portfolio query field.");
  const list = (value: unknown) => {
    if (!Array.isArray(value) || value.length > 100 ||
        value.some(x => typeof x !== "string" || !x ||
          x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
      throw new WorkInputError("INVALID", "Invalid portfolio filter.");
    return [...new Set(value as string[])];
  };
  for (const key of ["onlyPareto", "onlyNonDegrading"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid portfolio boolean filter.");
  }
  return {
    ...(raw.bundleIds === undefined ? {} : {
      bundleIds: list(raw.bundleIds),
    }),
    ...(raw.interventionIds === undefined ? {} : {
      interventionIds: list(raw.interventionIds),
    }),
    onlyPareto: raw.onlyPareto === true,
    onlyNonDegrading: raw.onlyNonDegrading === true,
    ...(raw.minimumAssignedGain === undefined ? {} : {
      minimumAssignedGain: integer(raw.minimumAssignedGain,
        "minimum assignment gain", 0, 10000),
    }),
    ...(raw.minimumCompletedGain === undefined ? {} : {
      minimumCompletedGain: integer(raw.minimumCompletedGain,
        "minimum completion gain", 0, 10000),
    }),
    offset: integer(raw.offset ?? 0, "portfolio offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "portfolio limit", 1, 500),
  };
}
export function queryIntegrityCapacityPortfolio(
  report: IntegrityCapacityPortfolioReport,
  query: IntegrityCapacityPortfolioQuery,
): IntegrityCapacityPortfolioPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.bundles.filter(x =>
    (!query.bundleIds || query.bundleIds.includes(x.bundleId)) &&
    (!query.interventionIds || query.interventionIds.every(id =>
      x.interventionIds.includes(id))) &&
    (!query.onlyPareto || report.paretoBundleIds.includes(x.bundleId)) &&
    (!query.onlyNonDegrading || !x.degraded) &&
    (query.minimumAssignedGain === undefined ||
      x.assignedDelta >= query.minimumAssignedGain) &&
    (query.minimumCompletedGain === undefined ||
      x.completedDelta >= query.minimumCompletedGain));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    bundles: selected.slice(offset, offset + limit),
  };
}
