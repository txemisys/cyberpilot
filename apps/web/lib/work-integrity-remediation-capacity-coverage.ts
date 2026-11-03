import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityExecutionCapacityPlan,
} from "./work-integrity-remediation-execution-capacity";
import type {
  IntegrityExecutionCapacityForecast,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";

export type IntegrityCapacityCoverageGroup = {
  key: string;
  candidates: number;
  assigned: number;
  unassigned: number;
  completedWithinHorizon: number;
  outsideHorizon: number;
  unavailable: number;
  effortPoints: number;
  assignedEffortPoints: number;
  completedEffortPoints: number;
  assignmentPercent: number;
  completionPercent: number;
  candidateIds: string[];
};
export type IntegrityCapacityCoverageDimension =
  | "PRIORITY" | "ACTION" | "NEXT_STEP" | "CASE" | "WORK_ITEM";
export type IntegrityCapacityCoverageReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  dimensions: Record<
    IntegrityCapacityCoverageDimension,
    IntegrityCapacityCoverageGroup[]
  >;
  uncovered: {
    candidateIds: string[];
    unassignedCandidateIds: string[];
    outsideHorizonCandidateIds: string[];
    withoutForecastCandidateIds: string[];
  };
  totals: {
    candidates: number;
    assigned: number;
    unassigned: number;
    completedWithinHorizon: number;
    outsideHorizon: number;
    unavailable: number;
    withoutForecast: number;
    effortPoints: number;
    completedEffortPoints: number;
    assignmentPercent: number;
    completionPercent: number;
  };
  limitation: string;
};
export type IntegrityCapacityCoverageQuery = {
  dimensions?: IntegrityCapacityCoverageDimension[];
  keys?: string[];
  onlyUncovered?: boolean;
  minimumCandidates?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityCoveragePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  groups: Array<{
    dimension: IntegrityCapacityCoverageDimension;
    group: IntegrityCapacityCoverageGroup;
  }>;
};
const dimensions: IntegrityCapacityCoverageDimension[] = [
  "PRIORITY", "ACTION", "NEXT_STEP", "CASE", "WORK_ITEM",
];
function record(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid capacity coverage query.");
  return value as Record<string, unknown>;
}
function list(value: unknown) {
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid coverage filter.");
  return [...new Set(value as string[])];
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
export function buildIntegrityCapacityCoverage(
  queue: IntegrityExecutionRemediationQueue,
  plan: IntegrityExecutionCapacityPlan,
  forecast: IntegrityExecutionCapacityForecast | null,
): IntegrityCapacityCoverageReport {
  if (queue.captureId !== plan.captureId ||
      (forecast && forecast.captureId !== plan.captureId))
    throw new WorkInputError("INVALID", "Capacity coverage capture mismatch.");
  const assigned = new Map(plan.assignments.map(x =>
    [x.candidateId, x]));
  const forecastTasks = new Map(forecast?.tasks.map(x =>
    [x.candidateId, x]) ?? []);
  const dimensionKeys: Record<
    IntegrityCapacityCoverageDimension,
    (item: IntegrityExecutionRemediationQueue["items"][number]) => string
  > = {
    PRIORITY: item => item.priority,
    ACTION: item => item.action,
    NEXT_STEP: item => item.recommendedNextStep,
    CASE: item => item.caseKey ?? "UNBOUND_CASE",
    WORK_ITEM: item => item.workItemId ?? "UNBOUND_WORK_ITEM",
  };
  const groups = Object.fromEntries(dimensions.map(dimension => {
    const grouped = new Map<string,
      IntegrityExecutionRemediationQueue["items"]>();
    for (const item of queue.items) {
      const key = dimensionKeys[dimension](item);
      const list = grouped.get(key) ?? [];
      list.push(item);
      grouped.set(key, list);
    }
    const entries: IntegrityCapacityCoverageGroup[] = [...grouped].map(
      ([key, items]) => {
        const selectedAssigned = items.filter(x =>
          assigned.has(x.candidateId));
        const completed = items.filter(x =>
          forecastTasks.get(x.candidateId)?.status === "SCHEDULED");
        const outside = items.filter(x =>
          forecastTasks.get(x.candidateId)?.status === "OUTSIDE_HORIZON");
        const unavailable = items.filter(x =>
          forecastTasks.get(x.candidateId)?.status === "CAPACITY_UNAVAILABLE");
        const effortPoints = items.reduce((sum, x) =>
          sum + (assigned.get(x.candidateId)?.effortPoints ??
            plan.unassigned.find(y =>
              y.candidateId === x.candidateId)?.effortPoints ?? 0), 0);
        const assignedEffortPoints = selectedAssigned.reduce((sum, x) =>
          sum + (assigned.get(x.candidateId)?.effortPoints ?? 0), 0);
        const completedEffortPoints = completed.reduce((sum, x) =>
          sum + (forecastTasks.get(x.candidateId)?.effortPoints ?? 0), 0);
        return {
          key, candidates: items.length,
          assigned: selectedAssigned.length,
          unassigned: items.length - selectedAssigned.length,
          completedWithinHorizon: completed.length,
          outsideHorizon: outside.length,
          unavailable: unavailable.length,
          effortPoints, assignedEffortPoints, completedEffortPoints,
          assignmentPercent: Math.round(100 *
            selectedAssigned.length / items.length),
          completionPercent: Math.round(100 *
            completed.length / items.length),
          candidateIds: items.map(x => x.candidateId).sort(),
        };
      });
    entries.sort((a, b) => b.unassigned - a.unassigned ||
      b.candidates - a.candidates || a.key.localeCompare(b.key));
    return [dimension, entries];
  })) as Record<
    IntegrityCapacityCoverageDimension,
    IntegrityCapacityCoverageGroup[]
  >;
  const unassignedCandidateIds = queue.items.filter(x =>
    !assigned.has(x.candidateId)).map(x => x.candidateId).sort();
  const outsideHorizonCandidateIds = queue.items.filter(x =>
    forecastTasks.get(x.candidateId)?.status === "OUTSIDE_HORIZON")
    .map(x => x.candidateId).sort();
  const withoutForecastCandidateIds = queue.items.filter(x =>
    !forecastTasks.has(x.candidateId)).map(x => x.candidateId).sort();
  const completed = queue.items.filter(x =>
    forecastTasks.get(x.candidateId)?.status === "SCHEDULED");
  const totalEffortPoints = queue.items.reduce((sum, x) =>
    sum + (assigned.get(x.candidateId)?.effortPoints ??
      plan.unassigned.find(y =>
        y.candidateId === x.candidateId)?.effortPoints ?? 0), 0);
  return {
    schemaVersion: 1, captureId: queue.captureId,
    evaluatedAt: plan.evaluatedAt, dimensions: groups,
    uncovered: {
      candidateIds: [...new Set([
        ...unassignedCandidateIds, ...outsideHorizonCandidateIds,
        ...withoutForecastCandidateIds,
      ])].sort(),
      unassignedCandidateIds, outsideHorizonCandidateIds,
      withoutForecastCandidateIds,
    },
    totals: {
      candidates: queue.items.length,
      assigned: assigned.size,
      unassigned: unassignedCandidateIds.length,
      completedWithinHorizon: completed.length,
      outsideHorizon: outsideHorizonCandidateIds.length,
      unavailable: queue.items.filter(x =>
        forecastTasks.get(x.candidateId)?.status === "CAPACITY_UNAVAILABLE").length,
      withoutForecast: withoutForecastCandidateIds.length,
      effortPoints: totalEffortPoints,
      completedEffortPoints: completed.reduce((sum, x) =>
        sum + (forecastTasks.get(x.candidateId)?.effortPoints ?? 0), 0),
      assignmentPercent: queue.items.length ?
        Math.round(100 * assigned.size / queue.items.length) : 100,
      completionPercent: queue.items.length ?
        Math.round(100 * completed.length / queue.items.length) : 100,
    },
    limitation: "Coverage reflects proposed allocations and modelled forecasts, not executed or independently verified remediation.",
  };
}
export function parseIntegrityCapacityCoverageQuery(
  value: unknown,
): IntegrityCapacityCoverageQuery {
  const raw = record(value);
  if (Object.keys(raw).some(x => ![
    "dimensions", "keys", "onlyUncovered",
    "minimumCandidates", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown coverage query field.");
  const selectedDimensions = raw.dimensions === undefined ? undefined :
    list(raw.dimensions);
  if (selectedDimensions?.some(x => !dimensions.includes(
    x as IntegrityCapacityCoverageDimension)))
    throw new WorkInputError("INVALID", "Unknown coverage dimension.");
  if (raw.onlyUncovered !== undefined &&
      typeof raw.onlyUncovered !== "boolean")
    throw new WorkInputError("INVALID", "Invalid coverage filter flag.");
  return {
    ...(selectedDimensions === undefined ? {} : {
      dimensions: selectedDimensions as IntegrityCapacityCoverageDimension[],
    }),
    ...(raw.keys === undefined ? {} : { keys: list(raw.keys) }),
    onlyUncovered: raw.onlyUncovered === true,
    ...(raw.minimumCandidates === undefined ? {} : {
      minimumCandidates: integer(raw.minimumCandidates,
        "minimum candidates", 0, 10000),
    }),
    offset: integer(raw.offset ?? 0, "coverage offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "coverage limit", 1, 1000),
  };
}
export function queryIntegrityCapacityCoverage(
  report: IntegrityCapacityCoverageReport,
  query: IntegrityCapacityCoverageQuery,
): IntegrityCapacityCoveragePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = dimensions.flatMap(dimension =>
    report.dimensions[dimension].map(group => ({ dimension, group })))
    .filter(x =>
      (!query.dimensions || query.dimensions.includes(x.dimension)) &&
      (!query.keys || query.keys.includes(x.group.key)) &&
      (!query.onlyUncovered || x.group.unassigned > 0 ||
        x.group.outsideHorizon > 0 ||
        x.group.completedWithinHorizon < x.group.candidates) &&
      (query.minimumCandidates === undefined ||
        x.group.candidates >= query.minimumCandidates));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    groups: selected.slice(offset, offset + limit),
  };
}
