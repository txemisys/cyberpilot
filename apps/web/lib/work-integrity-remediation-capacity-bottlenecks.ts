import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityExecutionCapacityPlan,
  IntegrityExecutionCapacityUnassignedReason,
} from "./work-integrity-remediation-execution-capacity";
import type {
  IntegrityExecutionCapacityForecast,
} from "./work-integrity-remediation-execution-capacity-forecast";
import type {
  IntegrityExecutionRemediationQueue,
} from "./work-integrity-remediation-execution-queue";

export type IntegrityCapacityBottleneckKind =
  | "NO_AVAILABLE_OWNER" | "INSUFFICIENT_SLOTS"
  | "INSUFFICIENT_EFFORT_BUDGET" | "CASE_CONCENTRATION"
  | "SHARED_WORK_ITEM" | "OWNER_CONFLICT"
  | "UNSUPPORTED_ACTION" | "UNSUPPORTED_NEXT_STEP"
  | "FORECAST_HORIZON" | "FORECAST_OVERLOAD";
export type IntegrityCapacityBottleneck = {
  id: string;
  kind: IntegrityCapacityBottleneckKind;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  candidateIds: string[];
  actorUserIds: string[];
  caseKeys: string[];
  affectedCandidates: number;
  affectedEffortPoints: number;
  maximumPriorityScore: number;
  explanation: string;
  suggestedIntervention: string;
  evidence: Record<string, number | string | boolean | null>;
};
export type IntegrityCapacityBottleneckPolicy = {
  criticalCandidateThreshold: number;
  highCandidateThreshold: number;
  criticalScoreThreshold: number;
  highScoreThreshold: number;
  maximumResults: number;
  includeForecast: boolean;
  includeActorOverload: boolean;
  actorOverloadPercent: number;
};
export type IntegrityCapacityBottleneckReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityCapacityBottleneckPolicy;
  bottlenecks: IntegrityCapacityBottleneck[];
  totals: {
    bottlenecks: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    affectedCandidates: number;
    affectedEffortPoints: number;
    distinctAffectedCandidates: number;
    byKind: Record<IntegrityCapacityBottleneckKind, number>;
    bySeverity: Record<IntegrityCapacityBottleneck["severity"], number>;
  };
  limitation: string;
};
export type IntegrityCapacityBottleneckQuery = {
  kinds?: IntegrityCapacityBottleneckKind[];
  severities?: IntegrityCapacityBottleneck["severity"][];
  candidateIds?: string[];
  actorUserIds?: string[];
  minimumAffected?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityBottleneckPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  bottlenecks: IntegrityCapacityBottleneck[];
};
const kinds: IntegrityCapacityBottleneckKind[] = [
  "NO_AVAILABLE_OWNER", "INSUFFICIENT_SLOTS",
  "INSUFFICIENT_EFFORT_BUDGET", "CASE_CONCENTRATION",
  "SHARED_WORK_ITEM", "OWNER_CONFLICT", "UNSUPPORTED_ACTION",
  "UNSUPPORTED_NEXT_STEP", "FORECAST_HORIZON", "FORECAST_OVERLOAD",
];
const severities: IntegrityCapacityBottleneck["severity"][] = [
  "CRITICAL", "HIGH", "MEDIUM", "LOW",
];
const defaultPolicy: IntegrityCapacityBottleneckPolicy = {
  criticalCandidateThreshold: 10,
  highCandidateThreshold: 3,
  criticalScoreThreshold: 200,
  highScoreThreshold: 120,
  maximumResults: 1000,
  includeForecast: true,
  includeActorOverload: true,
  actorOverloadPercent: 90,
};
const guidance: Record<IntegrityCapacityBottleneckKind, string> = {
  NO_AVAILABLE_OWNER: "Review authorized owners and their actual availability before proposing assignments.",
  INSUFFICIENT_SLOTS: "Reduce concurrency or increase verified owner availability.",
  INSUFFICIENT_EFFORT_BUDGET: "Reassess effort estimates or provide additional approved capacity.",
  CASE_CONCENTRATION: "Review per-case allocation limits and work dependencies.",
  SHARED_WORK_ITEM: "Reconcile shared work item ownership before duplicating remediation.",
  OWNER_CONFLICT: "Resolve the existing assignment conflict with the responsible owner.",
  UNSUPPORTED_ACTION: "Find a qualified owner for the remediation action.",
  UNSUPPORTED_NEXT_STEP: "Find a qualified owner for the required next step.",
  FORECAST_HORIZON: "Review deadline assumptions and forecast horizon.",
  FORECAST_OVERLOAD: "Review per-owner workload and redistribute where permitted.",
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
function stringList(value: unknown, label: string) {
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
export function parseIntegrityCapacityBottleneckPolicy(
  value: unknown,
): IntegrityCapacityBottleneckPolicy {
  if (value === undefined) return { ...defaultPolicy };
  const raw = record(value, "capacity bottleneck policy");
  if (Object.keys(raw).some(x => !Object.keys(defaultPolicy).includes(x)))
    throw new WorkInputError("INVALID", "Unknown bottleneck policy field.");
  const result = { ...defaultPolicy };
  for (const key of [
    "criticalCandidateThreshold", "highCandidateThreshold",
    "criticalScoreThreshold", "highScoreThreshold",
    "maximumResults", "actorOverloadPercent",
  ] as const) {
    if (raw[key] !== undefined)
      result[key] = integer(raw[key], key,
        key === "actorOverloadPercent" ? 1 : 0,
        key === "actorOverloadPercent" ? 100 :
        key === "maximumResults" ? 10000 : 100000);
  }
  if (result.highCandidateThreshold > result.criticalCandidateThreshold ||
      result.highScoreThreshold > result.criticalScoreThreshold)
    throw new WorkInputError("INVALID", "Reversed bottleneck thresholds.");
  for (const key of ["includeForecast", "includeActorOverload"] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid bottleneck policy flag.");
      result[key] = raw[key] as boolean;
    }
  }
  return result;
}
function severity(
  count: number,
  maxScore: number,
  policy: IntegrityCapacityBottleneckPolicy,
): IntegrityCapacityBottleneck["severity"] {
  if (count >= policy.criticalCandidateThreshold ||
      maxScore >= policy.criticalScoreThreshold) return "CRITICAL";
  if (count >= policy.highCandidateThreshold ||
      maxScore >= policy.highScoreThreshold) return "HIGH";
  if (count > 1 || maxScore > 0) return "MEDIUM";
  return "LOW";
}
const reasonKind: Record<
  IntegrityExecutionCapacityUnassignedReason,
  IntegrityCapacityBottleneckKind | null
> = {
  READY: null,
  QUEUE_LIMIT: "INSUFFICIENT_SLOTS",
  NO_CAPABLE_MEMBER: "NO_AVAILABLE_OWNER",
  CAPACITY_EXHAUSTED: "INSUFFICIENT_EFFORT_BUDGET",
  CASE_LIMIT: "CASE_CONCENTRATION",
  DUPLICATE_WORK_ITEM: "SHARED_WORK_ITEM",
  CONFLICTING_EXISTING_ASSIGNMENT: "OWNER_CONFLICT",
};
export function diagnoseIntegrityExecutionCapacity(
  queue: IntegrityExecutionRemediationQueue,
  plan: IntegrityExecutionCapacityPlan,
  forecast: IntegrityExecutionCapacityForecast | null,
  policy: IntegrityCapacityBottleneckPolicy = defaultPolicy,
): IntegrityCapacityBottleneckReport {
  if (queue.captureId !== plan.captureId ||
      (forecast && forecast.captureId !== plan.captureId))
    throw new WorkInputError("INVALID", "Bottleneck capture mismatch.");
  const items = new Map(queue.items.map(x => [x.candidateId, x]));
  const bottlenecks: IntegrityCapacityBottleneck[] = [];
  const add = (
    kind: IntegrityCapacityBottleneckKind,
    id: string,
    candidateIds: string[],
    actorUserIds: string[],
    evidence: Record<string, number | string | boolean | null>,
  ) => {
    if (!candidateIds.length) return;
    const unique = [...new Set(candidateIds)].sort();
    const matching = unique.map(x => items.get(x)).filter(
      (x): x is NonNullable<typeof x> => x !== undefined);
    const maximumPriorityScore = Math.max(0, ...matching.map(x => x.score));
    const affectedEffortPoints = unique.reduce((sum, id) =>
      sum + (plan.unassigned.find(x => x.candidateId === id)?.effortPoints ??
        plan.assignments.find(x => x.candidateId === id)?.effortPoints ?? 0), 0);
    bottlenecks.push({
      id: kind + ":" + id, kind,
      severity: severity(unique.length, maximumPriorityScore, policy),
      candidateIds: unique,
      actorUserIds: [...new Set(actorUserIds)].sort(),
      caseKeys: [...new Set(matching.map(x => x.caseKey).filter(
        (x): x is string => x !== null))].sort(),
      affectedCandidates: unique.length,
      affectedEffortPoints, maximumPriorityScore,
      explanation: kind.replaceAll("_", " ").toLowerCase() +
        " affects " + unique.length + " remediation candidates.",
      suggestedIntervention: guidance[kind],
      evidence,
    });
  };
  for (const reason of Object.keys(reasonKind) as
    IntegrityExecutionCapacityUnassignedReason[]) {
    const kind = reasonKind[reason];
    if (kind === null) continue;
    const matching = plan.unassigned.filter(x => x.reason === reason);
    add(kind, reason, matching.map(x => x.candidateId),
      matching.flatMap(x => x.eligibleMemberIds),
      { reason, affected: matching.length });
  }
  const withoutOwner = plan.unassigned.filter(x =>
    x.reason === "NO_CAPABLE_MEMBER");
  const missingActions = new Map<string, string[]>();
  const missingSteps = new Map<string, string[]>();
  for (const item of withoutOwner) {
    const queueItem = items.get(item.candidateId);
    if (!queueItem) continue;
    const action = missingActions.get(queueItem.action) ?? [];
    action.push(item.candidateId);
    missingActions.set(queueItem.action, action);
    const step = missingSteps.get(queueItem.recommendedNextStep) ?? [];
    step.push(item.candidateId);
    missingSteps.set(queueItem.recommendedNextStep, step);
  }
  for (const [action, ids] of missingActions)
    add("UNSUPPORTED_ACTION", action, ids, [],
      { action, affected: ids.length });
  for (const [step, ids] of missingSteps)
    add("UNSUPPORTED_NEXT_STEP", step, ids, [],
      { step, affected: ids.length });
  if (policy.includeForecast && forecast) {
    const outside = forecast.tasks.filter(x =>
      x.status === "OUTSIDE_HORIZON");
    add("FORECAST_HORIZON", "outside-horizon",
      outside.map(x => x.candidateId),
      outside.map(x => x.actorUserId).filter(
        (x): x is string => x !== null),
      { horizonDays: forecast.policy.maximumForecastDays,
        affected: outside.length });
    if (policy.includeActorOverload) {
      for (const actor of forecast.actors) {
        if (actor.utilizationPercent < policy.actorOverloadPercent)
          continue;
        const affected = forecast.tasks.filter(x =>
          x.actorUserId === actor.actorUserId);
        add("FORECAST_OVERLOAD", actor.actorUserId,
          affected.map(x => x.candidateId), [actor.actorUserId],
          { utilizationPercent: actor.utilizationPercent,
            thresholdPercent: policy.actorOverloadPercent });
      }
    }
  }
  const rank: Record<IntegrityCapacityBottleneck["severity"], number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
  };
  bottlenecks.sort((a, b) =>
    rank[b.severity] - rank[a.severity] ||
    b.affectedCandidates - a.affectedCandidates ||
    b.maximumPriorityScore - a.maximumPriorityScore ||
    a.id.localeCompare(b.id));
  const selected = bottlenecks.slice(0, policy.maximumResults);
  const byKind = Object.fromEntries(kinds.map(kind =>
    [kind, selected.filter(x => x.kind === kind).length])) as
    Record<IntegrityCapacityBottleneckKind, number>;
  const bySeverity = Object.fromEntries(severities.map(level =>
    [level, selected.filter(x => x.severity === level).length])) as
    Record<IntegrityCapacityBottleneck["severity"], number>;
  return {
    schemaVersion: 1, captureId: plan.captureId,
    evaluatedAt: plan.evaluatedAt, policy, bottlenecks: selected,
    totals: {
      bottlenecks: selected.length,
      critical: bySeverity.CRITICAL, high: bySeverity.HIGH,
      medium: bySeverity.MEDIUM, low: bySeverity.LOW,
      affectedCandidates: selected.reduce((sum, x) =>
        sum + x.affectedCandidates, 0),
      affectedEffortPoints: selected.reduce((sum, x) =>
        sum + x.affectedEffortPoints, 0),
      distinctAffectedCandidates: new Set(selected.flatMap(x =>
        x.candidateIds)).size,
      byKind, bySeverity,
    },
    limitation: "Bottlenecks are inferred from declared planning inputs and forecasts. They are not measured operational incidents or validated security findings.",
  };
}
export function parseIntegrityCapacityBottleneckQuery(
  value: unknown,
): IntegrityCapacityBottleneckQuery {
  const raw = record(value, "capacity bottleneck query");
  if (Object.keys(raw).some(x => ![
    "kinds", "severities", "candidateIds", "actorUserIds",
    "minimumAffected", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown bottleneck query field.");
  const selectedKinds = raw.kinds === undefined ? undefined :
    stringList(raw.kinds, "bottleneck kinds");
  const selectedSeverities = raw.severities === undefined ? undefined :
    stringList(raw.severities, "bottleneck severities");
  if (selectedKinds?.some(x => !kinds.includes(
    x as IntegrityCapacityBottleneckKind)) ||
    selectedSeverities?.some(x => !severities.includes(
      x as IntegrityCapacityBottleneck["severity"])))
    throw new WorkInputError("INVALID", "Unknown bottleneck filter value.");
  return {
    ...(selectedKinds === undefined ? {} :
      { kinds: selectedKinds as IntegrityCapacityBottleneckKind[] }),
    ...(selectedSeverities === undefined ? {} :
      { severities: selectedSeverities as IntegrityCapacityBottleneck["severity"][] }),
    ...(raw.candidateIds === undefined ? {} :
      { candidateIds: stringList(raw.candidateIds, "candidate IDs") }),
    ...(raw.actorUserIds === undefined ? {} :
      { actorUserIds: stringList(raw.actorUserIds, "actor IDs") }),
    ...(raw.minimumAffected === undefined ? {} :
      { minimumAffected: integer(raw.minimumAffected, "minimum affected", 0, 10000) }),
    offset: integer(raw.offset ?? 0, "bottleneck offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "bottleneck limit", 1, 1000),
  };
}
export function queryIntegrityCapacityBottlenecks(
  report: IntegrityCapacityBottleneckReport,
  query: IntegrityCapacityBottleneckQuery,
): IntegrityCapacityBottleneckPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.bottlenecks.filter(x =>
    (!query.kinds || query.kinds.includes(x.kind)) &&
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.candidateIds || x.candidateIds.some(id =>
      query.candidateIds!.includes(id))) &&
    (!query.actorUserIds || x.actorUserIds.some(id =>
      query.actorUserIds!.includes(id))) &&
    (query.minimumAffected === undefined ||
      x.affectedCandidates >= query.minimumAffected));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    bottlenecks: selected.slice(offset, offset + limit),
  };
}
