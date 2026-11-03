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
import type { IntegrityExecutionRemediationQueue } from "./work-integrity-remediation-execution-queue";

export type IntegrityCapacityIntervention =
  | { interventionId: string; kind: "ADD_MEMBER"; member: IntegrityExecutionCapacityMember }
  | { interventionId: string; kind: "REMOVE_MEMBER"; actorUserId: string }
  | { interventionId: string; kind: "INCREASE_SLOTS"; actorUserId: string; additionalSlots: number }
  | { interventionId: string; kind: "INCREASE_POINTS"; actorUserId: string; additionalPoints: number }
  | { interventionId: string; kind: "ENABLE_ACTION"; actorUserId: string; action: string }
  | { interventionId: string; kind: "ENABLE_STEP"; actorUserId: string; step: string }
  | { interventionId: string; kind: "UNBLOCK_CASE"; actorUserId: string; caseKey: string }
  | { interventionId: string; kind: "INCREASE_CASE_LIMIT"; additionalLimit: number }
  | { interventionId: string; kind: "INCREASE_FORECAST_DAYS"; additionalDays: number }
  | { interventionId: string; kind: "INCREASE_DAILY_THROUGHPUT"; additionalPoints: number };
export type IntegrityCapacityInterventionOutcome = {
  interventionId: string;
  kind: IntegrityCapacityIntervention["kind"];
  assignedDelta: number;
  completedDelta: number;
  unassignedDelta: number;
  outsideHorizonDelta: number;
  effortCompletedDelta: number;
  gainedCandidateIds: string[];
  lostCandidateIds: string[];
  reassignedCandidateIds: string[];
  improved: boolean;
  degraded: boolean;
  neutral: boolean;
  capacity: IntegrityExecutionCapacityPlan;
  forecast: IntegrityExecutionCapacityForecast;
};
export type IntegrityCapacityInterventionReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  baseline: {
    assigned: number;
    completedWithinHorizon: number;
    unassigned: number;
    outsideHorizon: number;
    completedEffortPoints: number;
  };
  outcomes: IntegrityCapacityInterventionOutcome[];
  recommendedInterventionIds: string[];
  totals: {
    evaluated: number;
    improved: number;
    degraded: number;
    neutral: number;
    maximumAssignedGain: number;
    maximumCompletionGain: number;
    maximumCompletedEffortGain: number;
  };
  limitation: string;
};
export type IntegrityCapacityInterventionQuery = {
  kinds?: IntegrityCapacityIntervention["kind"][];
  onlyImproved?: boolean;
  minimumAssignedGain?: number;
  minimumCompletionGain?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityInterventionPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  outcomes: IntegrityCapacityInterventionOutcome[];
};
const kinds: IntegrityCapacityIntervention["kind"][] = [
  "ADD_MEMBER", "REMOVE_MEMBER", "INCREASE_SLOTS", "INCREASE_POINTS",
  "ENABLE_ACTION", "ENABLE_STEP", "UNBLOCK_CASE", "INCREASE_CASE_LIMIT",
  "INCREASE_FORECAST_DAYS", "INCREASE_DAILY_THROUGHPUT",
];
function object(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function id(value: unknown, label: string) {
  if (typeof value !== "string" || !value || value.length > 150 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function integer(value: unknown, label: string, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function parseMember(value: unknown): IntegrityExecutionCapacityMember {
  const raw = object(value, "intervention member");
  const fields = [
    "actorUserId", "maximumConcurrent", "maximumPoints",
    "supportedActions", "supportedSteps", "excludedCaseKeys",
    "assignedCandidateIds",
  ];
  if (Object.keys(raw).some(key => !fields.includes(key)))
    throw new WorkInputError("INVALID", "Unknown intervention member field.");
  const array = (key: string) => {
    const value = raw[key];
    if (!Array.isArray(value) || value.length > 1000 ||
        value.some(x => typeof x !== "string" || !x ||
          x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)) ||
        new Set(value).size !== value.length)
      throw new WorkInputError("INVALID", "Invalid member list: " + key);
    return value as string[];
  };
  return {
    actorUserId: id(raw.actorUserId, "member ID"),
    maximumConcurrent: integer(raw.maximumConcurrent, "member slots", 0, 10000),
    maximumPoints: integer(raw.maximumPoints, "member points", 0, 1000000),
    supportedActions: array("supportedActions"),
    supportedSteps: array("supportedSteps"),
    excludedCaseKeys: array("excludedCaseKeys"),
    assignedCandidateIds: array("assignedCandidateIds"),
  };
}
export function parseIntegrityCapacityInterventions(
  value: unknown,
): IntegrityCapacityIntervention[] {
  if (!Array.isArray(value) || !value.length || value.length > 50)
    throw new WorkInputError("INVALID", "Invalid capacity interventions.");
  const interventions = value.map(item => {
    const raw = object(item, "capacity intervention");
    const interventionId = id(raw.interventionId, "intervention ID");
    if (!kinds.includes(raw.kind as IntegrityCapacityIntervention["kind"]))
      throw new WorkInputError("INVALID", "Unknown intervention kind.");
    const kind = raw.kind as IntegrityCapacityIntervention["kind"];
    const allowed = kind === "ADD_MEMBER" ? ["member"] :
      kind === "REMOVE_MEMBER" ? ["actorUserId"] :
      kind === "INCREASE_SLOTS" ? ["actorUserId", "additionalSlots"] :
      kind === "INCREASE_POINTS" ? ["actorUserId", "additionalPoints"] :
      kind === "ENABLE_ACTION" ? ["actorUserId", "action"] :
      kind === "ENABLE_STEP" ? ["actorUserId", "step"] :
      kind === "UNBLOCK_CASE" ? ["actorUserId", "caseKey"] :
      kind === "INCREASE_CASE_LIMIT" ? ["additionalLimit"] :
      kind === "INCREASE_FORECAST_DAYS" ? ["additionalDays"] :
      ["additionalPoints"];
    if (Object.keys(raw).some(key =>
      !["interventionId", "kind", ...allowed].includes(key)))
      throw new WorkInputError("INVALID", "Unknown intervention field.");
    if (kind === "ADD_MEMBER")
      return { interventionId, kind, member: parseMember(raw.member) };
    if (kind === "REMOVE_MEMBER")
      return { interventionId, kind, actorUserId: id(raw.actorUserId, "actor") };
    if (kind === "INCREASE_SLOTS")
      return { interventionId, kind,
        actorUserId: id(raw.actorUserId, "actor"),
        additionalSlots: integer(raw.additionalSlots, "additional slots", 1, 10000) };
    if (kind === "INCREASE_POINTS")
      return { interventionId, kind,
        actorUserId: id(raw.actorUserId, "actor"),
        additionalPoints: integer(raw.additionalPoints, "additional points", 1, 1000000) };
    if (kind === "ENABLE_ACTION")
      return { interventionId, kind,
        actorUserId: id(raw.actorUserId, "actor"),
        action: id(raw.action, "action") };
    if (kind === "ENABLE_STEP")
      return { interventionId, kind,
        actorUserId: id(raw.actorUserId, "actor"),
        step: id(raw.step, "step") };
    if (kind === "UNBLOCK_CASE")
      return { interventionId, kind,
        actorUserId: id(raw.actorUserId, "actor"),
        caseKey: id(raw.caseKey, "case key") };
    if (kind === "INCREASE_CASE_LIMIT")
      return { interventionId, kind,
        additionalLimit: integer(raw.additionalLimit, "additional case limit", 1, 10000) };
    if (kind === "INCREASE_FORECAST_DAYS")
      return { interventionId, kind,
        additionalDays: integer(raw.additionalDays, "additional days", 1, 365) };
    return { interventionId, kind: "INCREASE_DAILY_THROUGHPUT" as const,
      additionalPoints: integer(raw.additionalPoints, "additional daily points", 1, 10000) };
  });
  if (new Set(interventions.map(x => x.interventionId)).size !== interventions.length)
    throw new WorkInputError("INVALID", "Duplicate intervention ID.");
  return interventions;
}
function applyIntervention(
  members: readonly IntegrityExecutionCapacityMember[],
  capacityPolicy: IntegrityExecutionCapacityPolicy,
  forecastPolicy: IntegrityExecutionCapacityForecastPolicy,
  intervention: IntegrityCapacityIntervention,
) {
  let updated = members.map(member => ({
    ...member,
    supportedActions: [...member.supportedActions],
    supportedSteps: [...member.supportedSteps],
    excludedCaseKeys: [...member.excludedCaseKeys],
    assignedCandidateIds: [...member.assignedCandidateIds],
  }));
  const capacity = { ...capacityPolicy };
  const forecast = { ...forecastPolicy };
  if (intervention.kind === "ADD_MEMBER") {
    if (updated.some(x => x.actorUserId === intervention.member.actorUserId))
      throw new WorkInputError("INVALID", "Intervention member already exists.");
    updated.push({ ...intervention.member });
  } else if (intervention.kind === "INCREASE_CASE_LIMIT") {
    capacity.maximumCandidatesPerCase = integer(
      capacity.maximumCandidatesPerCase + intervention.additionalLimit,
      "resulting case limit", 1, 10000);
  } else if (intervention.kind === "INCREASE_FORECAST_DAYS") {
    forecast.maximumForecastDays = integer(
      forecast.maximumForecastDays + intervention.additionalDays,
      "resulting forecast days", 1, 365);
  } else if (intervention.kind === "INCREASE_DAILY_THROUGHPUT") {
    forecast.pointsPerDay = integer(
      forecast.pointsPerDay + intervention.additionalPoints,
      "resulting daily throughput", 1, 10000);
  } else {
    const actor = intervention.actorUserId;
    if (!updated.some(x => x.actorUserId === actor))
      throw new WorkInputError("INVALID", "Unknown intervention actor.");
    if (intervention.kind === "REMOVE_MEMBER") {
      if (updated.find(x => x.actorUserId === actor)!.assignedCandidateIds.length)
        throw new WorkInputError("INVALID", "Cannot remove member with existing assignments.");
      updated = updated.filter(x => x.actorUserId !== actor);
    } else {
      updated = updated.map(member => {
        if (member.actorUserId !== actor) return member;
        if (intervention.kind === "INCREASE_SLOTS")
          return { ...member, maximumConcurrent: integer(
            member.maximumConcurrent + intervention.additionalSlots,
            "resulting slots", 0, 10000) };
        if (intervention.kind === "INCREASE_POINTS")
          return { ...member, maximumPoints: integer(
            member.maximumPoints + intervention.additionalPoints,
            "resulting points", 0, 1000000) };
        if (intervention.kind === "ENABLE_ACTION")
          return { ...member, supportedActions: [
            ...new Set([...member.supportedActions, intervention.action]),
          ] };
        if (intervention.kind === "ENABLE_STEP")
          return { ...member, supportedSteps: [
            ...new Set([...member.supportedSteps, intervention.step]),
          ] };
        if (intervention.kind === "UNBLOCK_CASE")
          return { ...member, excludedCaseKeys: member.excludedCaseKeys.filter(
            x => x !== intervention.caseKey) };
        return member;
      });
    }
  }
  return { members: updated, capacityPolicy: capacity, forecastPolicy: forecast };
}
function candidateDelta(
  before: IntegrityExecutionCapacityPlan,
  after: IntegrityExecutionCapacityPlan,
) {
  const previous = new Map(before.assignments.map(x =>
    [x.candidateId, x.actorUserId]));
  const current = new Map(after.assignments.map(x =>
    [x.candidateId, x.actorUserId]));
  return {
    gainedCandidateIds: [...current.keys()].filter(x => !previous.has(x)).sort(),
    lostCandidateIds: [...previous.keys()].filter(x => !current.has(x)).sort(),
    reassignedCandidateIds: [...current].filter(([id, actor]) =>
      previous.has(id) && previous.get(id) !== actor)
      .map(([id]) => id).sort(),
  };
}
export function simulateIntegrityCapacityInterventions(
  queue: IntegrityExecutionRemediationQueue,
  members: readonly IntegrityExecutionCapacityMember[],
  evaluatedAt: string,
  capacityPolicy: IntegrityExecutionCapacityPolicy,
  forecastPolicy: IntegrityExecutionCapacityForecastPolicy,
  interventions: readonly IntegrityCapacityIntervention[],
): IntegrityCapacityInterventionReport {
  if (!interventions.length || interventions.length > 50)
    throw new WorkInputError("INVALID", "Invalid intervention collection.");
  if (new Set(interventions.map(x => x.interventionId)).size !== interventions.length)
    throw new WorkInputError("INVALID", "Duplicate intervention IDs.");
  const baselineCapacity = planIntegrityExecutionCapacity(
    queue, members, evaluatedAt, capacityPolicy);
  const baselineForecast = forecastIntegrityExecutionCapacity(
    baselineCapacity, queue, evaluatedAt, forecastPolicy);
  const outcomes = interventions.map(intervention => {
    const changed = applyIntervention(members, capacityPolicy,
      forecastPolicy, intervention);
    const capacity = planIntegrityExecutionCapacity(
      queue, changed.members, evaluatedAt, changed.capacityPolicy);
    const forecast = forecastIntegrityExecutionCapacity(
      capacity, queue, evaluatedAt, changed.forecastPolicy);
    const assignedDelta = capacity.totals.assigned -
      baselineCapacity.totals.assigned;
    const completedDelta = forecast.totals.completedWithinHorizon -
      baselineForecast.totals.completedWithinHorizon;
    const unassignedDelta = capacity.totals.unassigned -
      baselineCapacity.totals.unassigned;
    const outsideHorizonDelta = forecast.totals.outsideHorizon -
      baselineForecast.totals.outsideHorizon;
    const effortCompletedDelta = forecast.totals.completedPoints -
      baselineForecast.totals.completedPoints;
    const improved = assignedDelta > 0 || completedDelta > 0 ||
      unassignedDelta < 0 || outsideHorizonDelta < 0 ||
      effortCompletedDelta > 0;
    const degraded = assignedDelta < 0 || completedDelta < 0 ||
      unassignedDelta > 0 || outsideHorizonDelta > 0 ||
      effortCompletedDelta < 0;
    return {
      interventionId: intervention.interventionId,
      kind: intervention.kind,
      assignedDelta, completedDelta, unassignedDelta,
      outsideHorizonDelta, effortCompletedDelta,
      ...candidateDelta(baselineCapacity, capacity),
      improved, degraded, neutral: !improved && !degraded,
      capacity, forecast,
    };
  });
  const recommendedInterventionIds = outcomes.filter(x =>
    x.improved && !x.degraded).sort((a, b) =>
    b.completedDelta - a.completedDelta ||
    b.assignedDelta - a.assignedDelta ||
    b.effortCompletedDelta - a.effortCompletedDelta ||
    a.interventionId.localeCompare(b.interventionId))
    .map(x => x.interventionId);
  return {
    schemaVersion: 1, captureId: queue.captureId, evaluatedAt,
    baseline: {
      assigned: baselineCapacity.totals.assigned,
      completedWithinHorizon: baselineForecast.totals.completedWithinHorizon,
      unassigned: baselineCapacity.totals.unassigned,
      outsideHorizon: baselineForecast.totals.outsideHorizon,
      completedEffortPoints: baselineForecast.totals.completedPoints,
    },
    outcomes, recommendedInterventionIds,
    totals: {
      evaluated: outcomes.length,
      improved: outcomes.filter(x => x.improved).length,
      degraded: outcomes.filter(x => x.degraded).length,
      neutral: outcomes.filter(x => x.neutral).length,
      maximumAssignedGain: Math.max(0, ...outcomes.map(x => x.assignedDelta)),
      maximumCompletionGain: Math.max(0, ...outcomes.map(x => x.completedDelta)),
      maximumCompletedEffortGain: Math.max(0,
        ...outcomes.map(x => x.effortCompletedDelta)),
    },
    limitation: "Each intervention is simulated independently. Recommendations are based only on declared capacity and simplified forecasts, not authorization, actual staff availability, or security verification.",
  };
}
export function parseIntegrityCapacityInterventionQuery(
  value: unknown,
): IntegrityCapacityInterventionQuery {
  const raw = object(value, "intervention query");
  if (Object.keys(raw).some(x => ![
    "kinds", "onlyImproved", "minimumAssignedGain",
    "minimumCompletionGain", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown intervention query field.");
  const selectedKinds = raw.kinds === undefined ? undefined : raw.kinds;
  if (selectedKinds !== undefined &&
      (!Array.isArray(selectedKinds) || selectedKinds.length > kinds.length ||
        selectedKinds.some(x => !kinds.includes(x)) ||
        new Set(selectedKinds).size !== selectedKinds.length))
    throw new WorkInputError("INVALID", "Invalid intervention kinds.");
  if (raw.onlyImproved !== undefined && typeof raw.onlyImproved !== "boolean")
    throw new WorkInputError("INVALID", "Invalid intervention improvement filter.");
  return {
    ...(selectedKinds === undefined ? {} : {
      kinds: selectedKinds as IntegrityCapacityIntervention["kind"][],
    }),
    onlyImproved: raw.onlyImproved === true,
    ...(raw.minimumAssignedGain === undefined ? {} : {
      minimumAssignedGain: integer(raw.minimumAssignedGain,
        "minimum assignment gain", 0, 10000),
    }),
    ...(raw.minimumCompletionGain === undefined ? {} : {
      minimumCompletionGain: integer(raw.minimumCompletionGain,
        "minimum completion gain", 0, 10000),
    }),
    offset: integer(raw.offset ?? 0, "intervention offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "intervention limit", 1, 1000),
  };
}
export function queryIntegrityCapacityInterventions(
  report: IntegrityCapacityInterventionReport,
  query: IntegrityCapacityInterventionQuery,
): IntegrityCapacityInterventionPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 50;
  const selected = report.outcomes.filter(x =>
    (!query.kinds || query.kinds.includes(x.kind)) &&
    (!query.onlyImproved || (x.improved && !x.degraded)) &&
    (query.minimumAssignedGain === undefined ||
      x.assignedDelta >= query.minimumAssignedGain) &&
    (query.minimumCompletionGain === undefined ||
      x.completedDelta >= query.minimumCompletionGain));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    outcomes: selected.slice(offset, offset + limit),
  };
}
