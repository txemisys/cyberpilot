import { WorkInputError } from "./remediation-work-input";
import {
  planIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityMembers,
  parseIntegrityExecutionCapacityPolicy,
  type IntegrityExecutionCapacityMember,
  type IntegrityExecutionCapacityPlan,
  type IntegrityExecutionCapacityPolicy,
} from "./work-integrity-remediation-execution-capacity";
import {
  forecastIntegrityExecutionCapacity,
  parseIntegrityExecutionCapacityForecastPolicy,
  type IntegrityExecutionCapacityForecast,
  type IntegrityExecutionCapacityForecastPolicy,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";

export type IntegrityCapacityScenarioInput = {
  scenarioId: string;
  label: string;
  members: IntegrityExecutionCapacityMember[];
  capacityPolicy: IntegrityExecutionCapacityPolicy;
  forecastPolicy: IntegrityExecutionCapacityForecastPolicy;
};
export type IntegrityCapacityScenarioMetric = {
  scenarioId: string;
  label: string;
  assigned: number;
  unassigned: number;
  assignedPercent: number;
  availablePoints: number;
  remainingPoints: number;
  assignedEffortPoints: number;
  completedWithinHorizon: number;
  outsideHorizon: number;
  unavailable: number;
  forecastWorkingDays: number;
  forecastLastDate: string | null;
  forecastCompletedPoints: number;
  utilizationPercent: number;
  unassignedByReason: Record<string, number>;
};
export type IntegrityCapacityScenarioDelta = {
  scenarioId: string;
  baselineScenarioId: string;
  assignedDelta: number;
  unassignedDelta: number;
  assignedPercentDelta: number;
  availablePointsDelta: number;
  remainingPointsDelta: number;
  completedDelta: number;
  outsideHorizonDelta: number;
  unavailableDelta: number;
  completedPointsDelta: number;
  utilizationDelta: number;
  gainedCandidateIds: string[];
  lostCandidateIds: string[];
  changedActorAssignments: Array<{
    candidateId: string;
    beforeActorUserId: string;
    afterActorUserId: string;
  }>;
};
export type IntegrityCapacityScenarioResult = {
  scenarioId: string;
  label: string;
  metric: IntegrityCapacityScenarioMetric;
  delta: IntegrityCapacityScenarioDelta;
  capacity: IntegrityExecutionCapacityPlan;
  forecast: IntegrityExecutionCapacityForecast;
};
export type IntegrityCapacityScenarioComparison = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  baselineScenarioId: string;
  scenarios: IntegrityCapacityScenarioResult[];
  bestByAssigned: string | null;
  bestByCompletion: string | null;
  bestByUnassigned: string | null;
  paretoScenarioIds: string[];
  limitation: string;
};
export type IntegrityCapacityScenarioQuery = {
  scenarioIds?: string[];
  minimumAssigned?: number;
  maximumUnassigned?: number;
  minimumCompleted?: number;
  onlyPareto?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityScenarioPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  scenarios: IntegrityCapacityScenarioResult[];
};
function record(value: unknown, label: string) {
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
function stringList(value: unknown, label: string, maximum: number) {
  if (!Array.isArray(value) || value.length > maximum ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 150 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function validId(value: unknown, label: string) {
  if (typeof value !== "string" || !value ||
      value.length > 150 || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function timestamp(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid scenario evaluation time.");
}
export function parseIntegrityCapacityScenarios(
  value: unknown,
): IntegrityCapacityScenarioInput[] {
  if (!Array.isArray(value) || !value.length || value.length > 20)
    throw new WorkInputError("INVALID", "Invalid scenario collection.");
  const result = value.map((item, index) => {
    const raw = record(item, "scenario");
    if (Object.keys(raw).some(x => ![
      "scenarioId", "label", "members", "capacityPolicy",
      "forecastPolicy",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown scenario field.");
    const scenarioId = validId(raw.scenarioId, "scenario ID");
    const label = raw.label === undefined ?
      "Scenario " + (index + 1) : validId(raw.label, "scenario label");
    return {
      scenarioId, label,
      members: parseIntegrityExecutionCapacityMembers(raw.members),
      capacityPolicy: parseIntegrityExecutionCapacityPolicy(
        raw.capacityPolicy),
      forecastPolicy: parseIntegrityExecutionCapacityForecastPolicy(
        raw.forecastPolicy),
    };
  });
  if (new Set(result.map(x => x.scenarioId)).size !== result.length)
    throw new WorkInputError("INVALID", "Duplicate scenario ID.");
  return result;
}
function metric(
  scenarioId: string,
  label: string,
  capacity: IntegrityExecutionCapacityPlan,
  forecast: IntegrityExecutionCapacityForecast,
): IntegrityCapacityScenarioMetric {
  const available = capacity.totals.availablePoints;
  return {
    scenarioId, label,
    assigned: capacity.totals.assigned,
    unassigned: capacity.totals.unassigned,
    assignedPercent: capacity.totals.assignmentPercent,
    availablePoints: available,
    remainingPoints: capacity.totals.remainingPoints,
    assignedEffortPoints: capacity.totals.assignedEffortPoints,
    completedWithinHorizon: forecast.totals.completedWithinHorizon,
    outsideHorizon: forecast.totals.outsideHorizon,
    unavailable: forecast.totals.unavailable,
    forecastWorkingDays: forecast.totals.workingDays,
    forecastLastDate: forecast.totals.lastScheduledDate,
    forecastCompletedPoints: forecast.totals.completedPoints,
    utilizationPercent: available ?
      Math.round(100 * capacity.totals.assignedEffortPoints / available) : 0,
    unassignedByReason: { ...capacity.totals.byUnassignedReason },
  };
}
function delta(
  scenarioId: string,
  baselineId: string,
  baseline: IntegrityExecutionCapacityPlan,
  baselineMetric: IntegrityCapacityScenarioMetric,
  current: IntegrityExecutionCapacityPlan,
  currentMetric: IntegrityCapacityScenarioMetric,
): IntegrityCapacityScenarioDelta {
  const before = new Map(baseline.assignments.map(x =>
    [x.candidateId, x.actorUserId]));
  const after = new Map(current.assignments.map(x =>
    [x.candidateId, x.actorUserId]));
  return {
    scenarioId, baselineScenarioId: baselineId,
    assignedDelta: currentMetric.assigned - baselineMetric.assigned,
    unassignedDelta: currentMetric.unassigned - baselineMetric.unassigned,
    assignedPercentDelta: currentMetric.assignedPercent -
      baselineMetric.assignedPercent,
    availablePointsDelta: currentMetric.availablePoints -
      baselineMetric.availablePoints,
    remainingPointsDelta: currentMetric.remainingPoints -
      baselineMetric.remainingPoints,
    completedDelta: currentMetric.completedWithinHorizon -
      baselineMetric.completedWithinHorizon,
    outsideHorizonDelta: currentMetric.outsideHorizon -
      baselineMetric.outsideHorizon,
    unavailableDelta: currentMetric.unavailable -
      baselineMetric.unavailable,
    completedPointsDelta: currentMetric.forecastCompletedPoints -
      baselineMetric.forecastCompletedPoints,
    utilizationDelta: currentMetric.utilizationPercent -
      baselineMetric.utilizationPercent,
    gainedCandidateIds: [...after.keys()].filter(x => !before.has(x)).sort(),
    lostCandidateIds: [...before.keys()].filter(x => !after.has(x)).sort(),
    changedActorAssignments: [...after].filter(([id, actor]) =>
      before.has(id) && before.get(id) !== actor).map(([candidateId, actor]) => ({
      candidateId, beforeActorUserId: before.get(candidateId)!,
      afterActorUserId: actor,
    })).sort((a, b) => a.candidateId.localeCompare(b.candidateId)),
  };
}
function dominates(
  a: IntegrityCapacityScenarioMetric,
  b: IntegrityCapacityScenarioMetric,
) {
  return a.assigned >= b.assigned &&
    a.completedWithinHorizon >= b.completedWithinHorizon &&
    a.unassigned <= b.unassigned &&
    (a.assigned > b.assigned ||
      a.completedWithinHorizon > b.completedWithinHorizon ||
      a.unassigned < b.unassigned);
}
export function compareIntegrityCapacityScenarios(
  queue: IntegrityExecutionRemediationQueue,
  scenarios: readonly IntegrityCapacityScenarioInput[],
  evaluatedAt: string,
  baselineScenarioId?: string,
): IntegrityCapacityScenarioComparison {
  timestamp(evaluatedAt);
  if (!scenarios.length || scenarios.length > 20 ||
      new Set(scenarios.map(x => x.scenarioId)).size !== scenarios.length)
    throw new WorkInputError("INVALID", "Invalid comparison scenarios.");
  const baselineId = baselineScenarioId ?? scenarios[0]!.scenarioId;
  if (!scenarios.some(x => x.scenarioId === baselineId))
    throw new WorkInputError("INVALID", "Unknown baseline scenario.");
  const calculated = scenarios.map(scenario => {
    const capacity = planIntegrityExecutionCapacity(
      queue, scenario.members, evaluatedAt, scenario.capacityPolicy);
    const forecast = forecastIntegrityExecutionCapacity(
      capacity, queue, evaluatedAt, scenario.forecastPolicy);
    return {
      scenarioId: scenario.scenarioId, label: scenario.label,
      capacity, forecast,
      metric: metric(scenario.scenarioId, scenario.label, capacity, forecast),
    };
  });
  const baseline = calculated.find(x => x.scenarioId === baselineId)!;
  const results: IntegrityCapacityScenarioResult[] = calculated.map(x => ({
    ...x,
    delta: delta(x.scenarioId, baselineId, baseline.capacity,
      baseline.metric, x.capacity, x.metric),
  }));
  const best = (key: "assigned" | "completedWithinHorizon" | "unassigned",
    ascending: boolean) => {
    const sorted = [...results].sort((a, b) =>
      (ascending ? a.metric[key] - b.metric[key] :
        b.metric[key] - a.metric[key]) ||
      a.scenarioId.localeCompare(b.scenarioId));
    return sorted[0]?.scenarioId ?? null;
  };
  const paretoScenarioIds = results.filter(x =>
    !results.some(other => other.scenarioId !== x.scenarioId &&
      dominates(other.metric, x.metric))).map(x => x.scenarioId).sort();
  return {
    schemaVersion: 1, captureId: queue.captureId, evaluatedAt,
    baselineScenarioId: baselineId,
    scenarios: results,
    bestByAssigned: best("assigned", false),
    bestByCompletion: best("completedWithinHorizon", false),
    bestByUnassigned: best("unassigned", true),
    paretoScenarioIds,
    limitation: "Scenarios compare declared capacity and simulated forecasts only. They do not allocate personnel, change work, validate evidence, or establish security posture.",
  };
}
export function parseIntegrityCapacityScenarioQuery(
  value: unknown,
): IntegrityCapacityScenarioQuery {
  const raw = record(value, "scenario query");
  if (Object.keys(raw).some(x => ![
    "scenarioIds", "minimumAssigned", "maximumUnassigned",
    "minimumCompleted", "onlyPareto", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown scenario query field.");
  const offset = integer(raw.offset ?? 0, "scenario offset", 0, 1000000);
  const limit = integer(raw.limit ?? 20, "scenario limit", 1, 100);
  if (raw.onlyPareto !== undefined && typeof raw.onlyPareto !== "boolean")
    throw new WorkInputError("INVALID", "Invalid Pareto filter.");
  return {
    ...(raw.scenarioIds === undefined ? {} :
      { scenarioIds: stringList(raw.scenarioIds, "scenario IDs", 20) }),
    ...(raw.minimumAssigned === undefined ? {} : {
      minimumAssigned: integer(raw.minimumAssigned, "minimum assigned", 0, 10000),
    }),
    ...(raw.maximumUnassigned === undefined ? {} : {
      maximumUnassigned: integer(raw.maximumUnassigned, "maximum unassigned", 0, 10000),
    }),
    ...(raw.minimumCompleted === undefined ? {} : {
      minimumCompleted: integer(raw.minimumCompleted, "minimum completed", 0, 10000),
    }),
    onlyPareto: raw.onlyPareto === true, offset, limit,
  };
}
export function queryIntegrityCapacityScenarios(
  comparison: IntegrityCapacityScenarioComparison,
  query: IntegrityCapacityScenarioQuery,
): IntegrityCapacityScenarioPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 20;
  const selected = comparison.scenarios.filter(x =>
    (!query.scenarioIds || query.scenarioIds.includes(x.scenarioId)) &&
    (query.minimumAssigned === undefined ||
      x.metric.assigned >= query.minimumAssigned) &&
    (query.maximumUnassigned === undefined ||
      x.metric.unassigned <= query.maximumUnassigned) &&
    (query.minimumCompleted === undefined ||
      x.metric.completedWithinHorizon >= query.minimumCompleted) &&
    (!query.onlyPareto ||
      comparison.paretoScenarioIds.includes(x.scenarioId)));
  return {
    captureId: comparison.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    scenarios: selected.slice(offset, offset + limit),
  };
}
