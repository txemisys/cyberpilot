import { createHash } from "node:crypto";
import type { TimelineEvent, TimelineSource,
  TimelineIntegrity } from "./incident-operational-timeline-domain";

/** Operational measurements only: no Graph/EDR containment telemetry. */
export type MetricOutcome = "OBSERVED_INTERNAL" | "PARTIAL" | "UNKNOWN";
export type OperationalPriority = "P0" | "P1" | "P2";
export type SlaDisposition = "ON_TIME" | "DUE_SOON" | "OVERDUE" |
  "INDETERMINATE" | "NOT_APPLICABLE";
export type OperationalSlaPolicy = {
  schema: "cyberpilot.incident.internal-sla.policy.v1";
  policyId: string;
  effectiveAt: string;
  firstReviewTargetMinutes: number;
  firstAssignmentTargetMinutes: number;
  firstEscalationTargetMinutes: number;
  followupWarningMinutes: number;
  priorityTargetsMinutes: Record<OperationalPriority, number>;
  businessCalendar: "ELAPSED_UTC";
  externalServiceGuarantee: false;
};
export type HandoffSlaEvidence = {
  boardId: string;
  handoffId: string;
  controlId: string;
  priority: OperationalPriority;
  createdAt: string;
  dueAt: string;
  assignedAt: string | null;
  acceptedAt: string | null;
  lastEscalatedAt: string | null;
  updatedAt: string;
  status: string;
  assignedUserId: string | null;
  externalWrites: 0;
};
export type OperationalSlaMeasure = {
  metricId: string;
  subjectId: string;
  source: TimelineSource;
  outcome: MetricOutcome;
  disposition: SlaDisposition;
  startedAt: string | null;
  completedAt: string | null;
  dueAt: string | null;
  actualElapsedMinutes: number | null;
  targetMinutes: number | null;
  remainingMinutes: number | null;
  lateMinutes: number | null;
  completionIsInternal: true;
  coverageWarning: string | null;
  linkedEventIds: string[];
};
export type SlaSourceCoverage = {
  source: TimelineSource;
  availableEntries: number;
  verifiedEntries: number;
  incompleteEntries: number;
  conflicts: number;
  firstAt: string | null;
  lastAt: string | null;
  observedActors: number;
  reportedOutcome: MetricOutcome;
};
export type OperationalSlaSnapshot = {
  schema: "cyberpilot.incident.operational-sla.v1";
  organizationId: string;
  incidentId: string;
  incidentRevision: number;
  asOf: string;
  policy: OperationalSlaPolicy;
  sourceCoverage: SlaSourceCoverage[];
  measurements: OperationalSlaMeasure[];
  totals: {
    observed: number; partial: number; unknown: number;
    overdue: number; dueSoon: number; onTime: number;
    indeterminate: number; notApplicable: number;
  };
  handoffSummary: {
    total: number;
    unassigned: number;
    unacknowledged: number;
    escalatedInternal: number;
    pastExplicitDueAt: number;
    staleUnassigned: number;
    distinctAssignedUsers: number;
  };
  signal: "ACTION_REQUIRED" | "REVIEW_REQUIRED" | "NO_LOCAL_BREACH_OBSERVED";
  completeness: "COMPLETE" | "PARTIAL" | "UNKNOWN";
  sourceIntegrity: TimelineIntegrity;
  generatedFromInternalOnly: true;
  externalDispatches: 0;
  providerContainmentVerified: false;
  digest: string;
};
export type SlaDailyBucket = {
  day: string;
  source: TimelineSource;
  events: number;
  distinctActors: number;
  uniqueLedgers: number;
  incomplete: number;
  conflicted: number;
  createEvents: number;
  escalations: number;
  observationsOnly: true;
};
export type SlaActorWorkload = {
  userId: string;
  totalEvents: number;
  sourceCounts: Record<TimelineSource, number>;
  lastInternalActionAt: string;
  distinctSources: number;
  distinctLedgers: number;
  crossSourceActions: number;
  escalationEvents: number;
  evidenceReviewEvents: number;
  uncertainEvidenceEvents: number;
};
export type SlaIncidentHealth = {
  urgency: "CRITICAL" | "HIGH" | "ROUTINE" | "UNKNOWN";
  incompleteSources: TimelineSource[];
  activeWork: number;
  blockedWork: number;
  actionsNeedingReview: number;
  longestUnacceptedMinutes: number | null;
  latestEventAgeMinutes: number | null;
  reasons: string[];
  operatorAdvice: string[];
  providerOutcome: "UNKNOWN";
};
export type SlaForecast = {
  horizonMinutes: number;
  dueHandoffs: number;
  dueUnassigned: number;
  atRisk: number;
  alreadyOverdue: number;
  nextDeadlineAt: string | null;
  noExternalExecution: true;
};
const sources: TimelineSource[] = ["INCIDENT", "SITUATION_REVIEW",
  "TABLETOP_SESSION", "ASSURANCE_HANDOFF"];
const priorities: OperationalPriority[] = ["P0", "P1", "P2"];
const id = (x: unknown): x is string =>
  typeof x === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{3,127}$/.test(x);
const iso = (x: unknown): x is string => typeof x === "string" &&
  Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;
const reject = (code: string): never => { throw Error(code); };
function canonical(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(canonical);
  if (x !== null && typeof x === "object") {
    const r = x as Record<string, unknown>;
    return Object.fromEntries(Object.keys(r).sort()
      .filter(k => r[k] !== undefined).map(k => [k, canonical(r[k])]));
  }
  return x;
}
export function slaDigest(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value))).digest("hex");
}
const min = (later: string, earlier: string) =>
  Math.max(0, Math.floor((Date.parse(later) - Date.parse(earlier)) / 60000));
function elapsed(later: string | null, earlier: string | null) {
  return later !== null && earlier !== null && iso(later) && iso(earlier) &&
    later >= earlier ? min(later, earlier) : null;
}
function addMinutes(start: string, minutes: number) {
  return new Date(Date.parse(start) + minutes * 60000).toISOString();
}
const priorityOrder = (value: OperationalPriority) => priorities.indexOf(value);
export function validateOperationalSlaPolicy(policy: OperationalSlaPolicy) {
  const errors: string[] = [];
  if (policy?.schema !== "cyberpilot.incident.internal-sla.policy.v1" ||
      !id(policy.policyId) || !iso(policy.effectiveAt))
    errors.push("SLA_POLICY_IDENTITY_INVALID");
  const fields = ["firstReviewTargetMinutes",
    "firstAssignmentTargetMinutes", "firstEscalationTargetMinutes",
    "followupWarningMinutes"] as const;
  if (fields.some(field => !Number.isSafeInteger(policy?.[field]) ||
      policy[field] < 1 || policy[field] > 525600))
    errors.push("SLA_POLICY_TARGET_INVALID");
  if (!policy?.priorityTargetsMinutes ||
      priorities.some(priority =>
        !Number.isSafeInteger(policy.priorityTargetsMinutes[priority]) ||
        policy.priorityTargetsMinutes[priority] < 1 ||
        policy.priorityTargetsMinutes[priority] > 525600))
    errors.push("SLA_PRIORITY_TARGET_INVALID");
  if (policy?.businessCalendar !== "ELAPSED_UTC" ||
      policy?.externalServiceGuarantee !== false)
    errors.push("SLA_POLICY_EXTERNAL_CLAIM_DENIED");
  return errors;
}
export function validateHandoffSlaEvidence(item: HandoffSlaEvidence) {
  const problems: string[] = [];
  if (![item?.boardId, item?.handoffId, item?.controlId]
      .every(id) || !priorities.includes(item?.priority))
    problems.push("SLA_HANDOFF_IDENTITY_INVALID");
  if (![item?.createdAt, item?.dueAt, item?.updatedAt].every(iso) ||
      [item?.acceptedAt, item?.assignedAt,
        item?.lastEscalatedAt].some(v => v !== null && !iso(v)))
    problems.push("SLA_HANDOFF_TIMESTAMP_INVALID");
  if (item?.assignedUserId !== null && !id(item?.assignedUserId))
    problems.push("SLA_HANDOFF_ACTOR_INVALID");
  if (typeof item?.status !== "string" || item.status.length > 48)
    problems.push("SLA_HANDOFF_STATUS_INVALID");
  if (item?.externalWrites !== 0)
    problems.push("SLA_HANDOFF_FALSE_PROVIDER_CLAIM");
  if (iso(item?.dueAt) && iso(item?.createdAt) &&
      item.dueAt < item.createdAt)
    problems.push("SLA_HANDOFF_DEADLINE_PRECEDES_CREATION");
  if (item?.acceptedAt !== null && item?.assignedAt === null)
    problems.push("SLA_HANDOFF_UNASSIGNED_ACCEPTANCE");
  if (item?.assignedAt && item?.acceptedAt &&
      item.acceptedAt < item.assignedAt)
    problems.push("SLA_HANDOFF_ACCEPTANCE_PRECEDES_ASSIGNMENT");
  return problems;
}
function measure(input: {
  metricId: string; subjectId: string; source: TimelineSource;
  startedAt: string | null; completedAt: string | null;
  dueAt: string | null; targetMinutes: number | null;
  sourceOutcome: MetricOutcome; asOf: string; warning: string | null;
  linkedEventIds: string[];
}): OperationalSlaMeasure {
  const actual = elapsed(input.completedAt, input.startedAt);
  const current = elapsed(input.asOf, input.startedAt);
  const end = input.completedAt ?? input.asOf;
  const remaining = input.dueAt && iso(input.dueAt) ?
    Math.ceil((Date.parse(input.dueAt) - Date.parse(end)) / 60000) : null;
  const late = remaining === null ? null : Math.max(0, -remaining);
  const disposition: SlaDisposition =
    input.startedAt === null || input.dueAt === null ||
      input.sourceOutcome === "UNKNOWN" ? "INDETERMINATE" :
    input.completedAt !== null && late !== null && late > 0 ? "OVERDUE" :
    input.completedAt !== null ? "ON_TIME" :
    late !== null && late > 0 ? "OVERDUE" :
    remaining !== null && remaining <= 60 ? "DUE_SOON" :
    "ON_TIME";
  return {
    metricId: input.metricId, subjectId: input.subjectId,
    source: input.source, outcome: input.sourceOutcome,
    disposition, startedAt: input.startedAt, completedAt: input.completedAt,
    dueAt: input.dueAt, actualElapsedMinutes: actual,
    targetMinutes: input.targetMinutes, remainingMinutes: remaining,
    lateMinutes: late, completionIsInternal: true,
    coverageWarning: input.warning,
    linkedEventIds: input.linkedEventIds.slice(0, 30),
  };
}
function sortedEvents(events: TimelineEvent[], orgId: string,
  incidentId: string, asOf: string) {
  if (!Array.isArray(events) || events.length > 15000)
    reject("SLA_EVENT_INVENTORY_TOO_LARGE");
  for (const event of events) {
    if (event.organizationId !== orgId || event.incidentId !== incidentId)
      reject("SLA_CROSS_TENANT_EVENT");
    if (!iso(event.occurredAt) || event.occurredAt > asOf)
      reject("SLA_EVENT_FUTURE_OR_INVALID");
    if (event.providerWrites !== 0 ||
        event.providerOutcomeIndependentlyVerified !== false)
      reject("SLA_FALSE_PROVIDER_CLAIM");
  }
  const unique = new Set<string>();
  for (const event of events) {
    const key = [event.source, event.sourceId, event.sourceRevision].join(":");
    if (unique.has(key)) reject("SLA_DUPLICATE_EVENT_REVISION");
    unique.add(key);
  }
  return [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.source.localeCompare(b.source) ||
    a.sourceId.localeCompare(b.sourceId) ||
    a.sourceRevision - b.sourceRevision);
}
function firstMatching(events: TimelineEvent[], test: (e: TimelineEvent) =>
  boolean): TimelineEvent | null {
  return events.find(test) ?? null;
}
export function analyzeOperationalSla(args: {
  organizationId: string; incidentId: string; incidentRevision: number;
  asOf: string; policy: OperationalSlaPolicy;
  events: TimelineEvent[]; handoffs: HandoffSlaEvidence[];
  inventoryComplete: boolean;
}): OperationalSlaSnapshot {
  if (!id(args.organizationId) || !id(args.incidentId) ||
      !Number.isSafeInteger(args.incidentRevision) ||
      args.incidentRevision < 1 || !iso(args.asOf))
    reject("SLA_CONTEXT_INVALID");
  const policyProblems = validateOperationalSlaPolicy(args.policy);
  if (policyProblems.length) reject(policyProblems.join(","));
  if (!Array.isArray(args.handoffs) || args.handoffs.length > 3000)
    reject("SLA_HANDOFF_INVENTORY_TOO_LARGE");
  const distinctHandoffs = new Set<string>();
  for (const item of args.handoffs) {
    const problems = validateHandoffSlaEvidence(item);
    if (problems.length) reject(problems.join(","));
    const key = item.boardId + "/" + item.handoffId;
    if (distinctHandoffs.has(key)) reject("SLA_HANDOFF_DUPLICATE");
    distinctHandoffs.add(key);
    if (item.createdAt > args.asOf) reject("SLA_HANDOFF_FUTURE");
  }
  const events = sortedEvents(args.events, args.organizationId,
    args.incidentId, args.asOf);
  const sourceCoverage: SlaSourceCoverage[] = sources.map(source => {
    const rows = events.filter(x => x.source === source);
    const incompleteEntries = rows.filter(x =>
      x.sourceIntegrity === "INCOMPLETE").length;
    const conflicts = rows.filter(x =>
      x.sourceIntegrity === "CONFLICT").length;
    return {
      source, availableEntries: rows.length,
      verifiedEntries: rows.filter(x => x.sourceIntegrity === "VERIFIED").length,
      incompleteEntries, conflicts,
      firstAt: rows[0]?.occurredAt ?? null,
      lastAt: rows.at(-1)?.occurredAt ?? null,
      observedActors: new Set(rows.map(x => x.actorUserId)).size,
      reportedOutcome: conflicts || incompleteEntries ||
        !args.inventoryComplete ? "PARTIAL" : rows.length ?
        "OBSERVED_INTERNAL" : "UNKNOWN",
    };
  });
  const sourceIntegrity: TimelineIntegrity = sourceCoverage.some(x =>
    x.conflicts > 0) ? "CONFLICT" :
    sourceCoverage.some(x => x.incompleteEntries > 0) ||
      !args.inventoryComplete ? "INCOMPLETE" : "VERIFIED";
  const start = firstMatching(events, e => e.source === "INCIDENT" &&
    e.operation === "CREATE");
  const firstReview = firstMatching(events, e =>
    e.source === "SITUATION_REVIEW" &&
    ["BEGIN_REVIEW", "ACKNOWLEDGE"].includes(e.operation));
  const firstAssignment = firstMatching(events, e =>
    e.source === "ASSURANCE_HANDOFF" && e.operation === "ASSIGN");
  const firstEscalation = firstMatching(events, e =>
    e.source === "ASSURANCE_HANDOFF" &&
    e.operation === "ESCALATE_INTERNAL");
  const startOutcome: MetricOutcome = start === null ? "UNKNOWN" :
    start.sourceIntegrity === "VERIFIED" ? "OBSERVED_INTERNAL" : "PARTIAL";
  const interval = (metricId: string, target: number,
    done: TimelineEvent | null, source: TimelineSource) =>
    measure({
      metricId, subjectId: args.incidentId, source,
      startedAt: start?.occurredAt ?? null,
      completedAt: done?.occurredAt ?? null,
      dueAt: start ? addMinutes(start.occurredAt, target) : null,
      targetMinutes: target, asOf: args.asOf,
      sourceOutcome: !start ? "UNKNOWN" :
        !args.inventoryComplete ||
        startOutcome !== "OBSERVED_INTERNAL" ||
        done?.sourceIntegrity === "INCOMPLETE" ||
        done?.sourceIntegrity === "CONFLICT" ? "PARTIAL" :
          "OBSERVED_INTERNAL",
      warning: !start ? "INCIDENT_CREATION_NOT_OBSERVED" :
        !args.inventoryComplete ? "EVENT_INVENTORY_INCOMPLETE" :
        done?.sourceIntegrity !== "VERIFIED" && done !== null ?
          "COMPLETION_NOT_INDEPENDENTLY_VERIFIED" :
        startOutcome !== "OBSERVED_INTERNAL" ?
          "INCIDENT_SOURCE_INCOMPLETE" : null,
      linkedEventIds: [start?.eventId, done?.eventId]
        .filter((x): x is string => Boolean(x)),
    });
  const measurements: OperationalSlaMeasure[] = [
    interval("FIRST_INTERNAL_REVIEW", args.policy.firstReviewTargetMinutes,
      firstReview, "SITUATION_REVIEW"),
    interval("FIRST_INTERNAL_ASSIGNMENT",
      args.policy.firstAssignmentTargetMinutes, firstAssignment,
      "ASSURANCE_HANDOFF"),
    interval("FIRST_INTERNAL_ESCALATION",
      args.policy.firstEscalationTargetMinutes, firstEscalation,
      "ASSURANCE_HANDOFF"),
  ];
  const grouped = new Map<string, TimelineEvent[]>();
  for (const e of events.filter(e => e.source === "ASSURANCE_HANDOFF")) {
    const list = grouped.get(e.sourceId) ?? [];
    list.push(e);
    grouped.set(e.sourceId, list);
  }
  for (const item of args.handoffs) {
    const related = grouped.get(item.boardId) ?? [];
    const assignment = related.filter(x => x.operation === "ASSIGN");
    const accepted = related.filter(x => x.operation === "ACCEPT");
    const escalated = related.filter(x => x.operation === "ESCALATE_INTERNAL");
    const assignmentTarget = args.policy.priorityTargetsMinutes[item.priority];
    measurements.push(measure({
      metricId: "HANDOFF_ASSIGNMENT:" + item.handoffId,
      subjectId: item.boardId + ":" + item.handoffId,
      source: "ASSURANCE_HANDOFF",
      startedAt: item.createdAt,
      completedAt: item.assignedAt,
      dueAt: addMinutes(item.createdAt, assignmentTarget),
      targetMinutes: assignmentTarget, asOf: args.asOf,
      sourceOutcome: item.assignedAt === null && related.length === 0 ?
        "UNKNOWN" : "PARTIAL",
      warning: "HANDOFF_EVENT_SCOPE_NOT_INDEPENDENTLY_REPLAYED",
      linkedEventIds: assignment.map(x => x.eventId),
    }));
    measurements.push(measure({
      metricId: "HANDOFF_ACCEPTANCE:" + item.handoffId,
      subjectId: item.boardId + ":" + item.handoffId,
      source: "ASSURANCE_HANDOFF",
      startedAt: item.assignedAt,
      completedAt: item.acceptedAt,
      dueAt: item.dueAt, targetMinutes: null, asOf: args.asOf,
      sourceOutcome: item.assignedAt ? "PARTIAL" : "UNKNOWN",
      warning: "HANDOFF_ACCEPTANCE_INTERNAL_ONLY",
      linkedEventIds: accepted.map(x => x.eventId),
    }));
    if (item.lastEscalatedAt || escalated.length)
      measurements.push(measure({
        metricId: "HANDOFF_ESCALATION:" + item.handoffId,
        subjectId: item.boardId + ":" + item.handoffId,
        source: "ASSURANCE_HANDOFF",
        startedAt: item.createdAt,
        completedAt: item.lastEscalatedAt,
        dueAt: item.dueAt, targetMinutes: null,
        asOf: args.asOf, sourceOutcome: "PARTIAL",
        warning: "ESCALATION_NOT_EXTERNAL_DISPATCH",
        linkedEventIds: escalated.map(x => x.eventId),
      }));
  }
  const totals = {
    observed: measurements.filter(x => x.outcome === "OBSERVED_INTERNAL").length,
    partial: measurements.filter(x => x.outcome === "PARTIAL").length,
    unknown: measurements.filter(x => x.outcome === "UNKNOWN").length,
    overdue: measurements.filter(x => x.disposition === "OVERDUE").length,
    dueSoon: measurements.filter(x => x.disposition === "DUE_SOON").length,
    onTime: measurements.filter(x => x.disposition === "ON_TIME").length,
    indeterminate: measurements.filter(x =>
      x.disposition === "INDETERMINATE").length,
    notApplicable: measurements.filter(x =>
      x.disposition === "NOT_APPLICABLE").length,
  };
  const handoffSummary = {
    total: args.handoffs.length,
    unassigned: args.handoffs.filter(x => x.assignedAt === null).length,
    unacknowledged: args.handoffs.filter(x =>
      x.assignedAt !== null && x.acceptedAt === null).length,
    escalatedInternal: args.handoffs.filter(x =>
      x.lastEscalatedAt !== null).length,
    pastExplicitDueAt: args.handoffs.filter(x =>
      x.dueAt < args.asOf && x.acceptedAt === null).length,
    staleUnassigned: args.handoffs.filter(x =>
      x.assignedAt === null &&
      min(args.asOf, x.createdAt) >=
        args.policy.priorityTargetsMinutes[x.priority]).length,
    distinctAssignedUsers: new Set(args.handoffs
      .flatMap(x => x.assignedUserId ? [x.assignedUserId] : [])).size,
  };
  const completeness = !args.inventoryComplete ? "UNKNOWN" :
    sourceIntegrity === "VERIFIED" ? "COMPLETE" : "PARTIAL";
  const signal = totals.overdue || handoffSummary.pastExplicitDueAt ||
    handoffSummary.staleUnassigned ? "ACTION_REQUIRED" :
    totals.unknown || completeness !== "COMPLETE" || totals.partial ||
    totals.dueSoon ? "REVIEW_REQUIRED" : "NO_LOCAL_BREACH_OBSERVED";
  const snapshot: Omit<OperationalSlaSnapshot, "digest"> = {
    schema: "cyberpilot.incident.operational-sla.v1",
    organizationId: args.organizationId, incidentId: args.incidentId,
    incidentRevision: args.incidentRevision, asOf: args.asOf,
    policy: args.policy, sourceCoverage, measurements, totals,
    handoffSummary, signal, completeness, sourceIntegrity,
    generatedFromInternalOnly: true,
    externalDispatches: 0, providerContainmentVerified: false,
  };
  return { ...snapshot, digest: slaDigest(snapshot) };
}
export function calculateSlaDailyBuckets(events: TimelineEvent[],
  from: string, to: string): SlaDailyBucket[] {
  if (!iso(from) || !iso(to) || from > to ||
      Date.parse(to) - Date.parse(from) > 366 * 86400000)
    reject("SLA_TREND_RANGE_INVALID");
  const store = new Map<string, TimelineEvent[]>();
  for (const e of events) {
    if (e.occurredAt < from || e.occurredAt > to) continue;
    const day = e.occurredAt.slice(0, 10);
    const key = day + "/" + e.source;
    const bucket = store.get(key) ?? [];
    bucket.push(e); store.set(key, bucket);
  }
  const result: SlaDailyBucket[] = [];
  for (const [key, rows] of store) {
    const [day, source] = key.split("/") as [string, TimelineSource];
    result.push({
      day, source, events: rows.length,
      distinctActors: new Set(rows.map(x => x.actorUserId)).size,
      uniqueLedgers: new Set(rows.map(x => x.sourceId)).size,
      incomplete: rows.filter(x => x.sourceIntegrity === "INCOMPLETE").length,
      conflicted: rows.filter(x => x.sourceIntegrity === "CONFLICT").length,
      createEvents: rows.filter(x => x.operation === "CREATE").length,
      escalations: rows.filter(x =>
        x.operation === "ESCALATE_INTERNAL").length,
      observationsOnly: true,
    });
  }
  return result.sort((a, b) =>
    a.day.localeCompare(b.day) || a.source.localeCompare(b.source));
}
export function calculateSlaActorWorkloads(events: TimelineEvent[],
  maxActors = 100): SlaActorWorkload[] {
  if (!Number.isSafeInteger(maxActors) || maxActors < 1 || maxActors > 500)
    reject("SLA_WORKLOAD_LIMIT_INVALID");
  const actors = new Map<string, TimelineEvent[]>();
  for (const e of events) {
    const rows = actors.get(e.actorUserId) ?? [];
    rows.push(e); actors.set(e.actorUserId, rows);
  }
  const result: SlaActorWorkload[] = [];
  for (const [userId, rows] of actors) {
    const sourceCounts = Object.fromEntries(sources.map(source =>
      [source, rows.filter(x => x.source === source).length])) as
      Record<TimelineSource, number>;
    result.push({
      userId, totalEvents: rows.length, sourceCounts,
      lastInternalActionAt: rows.reduce((max, x) =>
        max > x.occurredAt ? max : x.occurredAt, rows[0].occurredAt),
      distinctSources: Object.values(sourceCounts).filter(x => x > 0).length,
      distinctLedgers: new Set(rows.map(x =>
        x.source + ":" + x.sourceId)).size,
      crossSourceActions: rows.filter(x =>
        x.source !== "INCIDENT").length,
      escalationEvents: rows.filter(x =>
        x.operation === "ESCALATE_INTERNAL").length,
      evidenceReviewEvents: rows.filter(x =>
        ["ACKNOWLEDGE", "RECORD_FINDING", "NEEDS_EVIDENCE"]
          .includes(x.operation)).length,
      uncertainEvidenceEvents: rows.filter(x =>
        x.sourceIntegrity !== "VERIFIED").length,
    });
  }
  return result.sort((a, b) => b.totalEvents - a.totalEvents ||
    a.userId.localeCompare(b.userId)).slice(0, maxActors);
}
export function forecastInternalDeadlines(
  snapshot: OperationalSlaSnapshot, horizons: number[],
): SlaForecast[] {
  if (snapshot.digest !== slaDigest({ ...snapshot, digest: undefined }))
    reject("SLA_SNAPSHOT_DIGEST_INVALID");
  if (!Array.isArray(horizons) || horizons.length > 20 ||
      horizons.some(h => !Number.isSafeInteger(h) || h < 1 || h > 525600))
    reject("SLA_FORECAST_HORIZON_INVALID");
  return [...new Set(horizons)].sort((a, b) => a - b).map(horizonMinutes => {
    const rows = snapshot.measurements.filter(x =>
      x.metricId.startsWith("HANDOFF_") &&
      x.completedAt === null && x.dueAt !== null);
    const cutoff = addMinutes(snapshot.asOf, horizonMinutes);
    const near = rows.filter(x => x.dueAt !== null &&
      x.dueAt <= cutoff);
    const dueUnassigned = near.filter(x =>
      x.metricId.startsWith("HANDOFF_ASSIGNMENT")).length;
    return {
      horizonMinutes, dueHandoffs: near.length,
      dueUnassigned,
      atRisk: near.filter(x => x.disposition === "DUE_SOON").length,
      alreadyOverdue: near.filter(x =>
        x.disposition === "OVERDUE").length,
      nextDeadlineAt: near.reduce<string | null>((earliest, x) =>
        x.dueAt !== null && (earliest === null || x.dueAt < earliest) ?
          x.dueAt : earliest, null),
      noExternalExecution: true as const,
    };
  });
}
export function assessIncidentOperationalHealth(
  snapshot: OperationalSlaSnapshot, events: TimelineEvent[],
): SlaIncidentHealth {
  if (snapshot.digest !== slaDigest({ ...snapshot, digest: undefined }))
    reject("SLA_SNAPSHOT_DIGEST_INVALID");
  const incompleteSources = snapshot.sourceCoverage.filter(x =>
    x.reportedOutcome !== "OBSERVED_INTERNAL").map(x => x.source);
  const active = snapshot.measurements.filter(x =>
    x.completedAt === null && x.startedAt !== null);
  const blocked = active.filter(x =>
    x.disposition === "OVERDUE" || x.outcome === "UNKNOWN");
  const latestAt = events.length ?
    events.map(x => x.occurredAt).sort().at(-1) ?? null : null;
  const latestEventAgeMinutes = latestAt ?
    elapsed(snapshot.asOf, latestAt) : null;
  const unaccepted = snapshot.measurements.filter(x =>
    x.metricId.startsWith("HANDOFF_ACCEPTANCE:") &&
    x.completedAt === null).map(x =>
    elapsed(snapshot.asOf, x.startedAt)).filter((x): x is number =>
      x !== null);
  const longestUnacceptedMinutes = unaccepted.length ?
    Math.max(...unaccepted) : null;
  const reasons: string[] = [];
  const operatorAdvice: string[] = [];
  if (snapshot.handoffSummary.pastExplicitDueAt) {
    reasons.push("EXPLICIT_HANDOFF_DUE_AT_BREACHED");
    operatorAdvice.push("Review overdue internal handoffs and ownership.");
  }
  if (snapshot.handoffSummary.staleUnassigned) {
    reasons.push("INTERNAL_ASSIGNMENT_TARGET_EXCEEDED");
    operatorAdvice.push("Assign an active authorized owner internally.");
  }
  if (snapshot.sourceIntegrity === "CONFLICT") {
    reasons.push("SOURCE_INTEGRITY_CONFLICT");
    operatorAdvice.push("Preserve evidence and investigate the ledger mismatch.");
  }
  if (incompleteSources.length) {
    reasons.push("SOURCE_COVERAGE_INCOMPLETE");
    operatorAdvice.push("Collect independent source verification before closure.");
  }
  if (latestEventAgeMinutes === null) {
    reasons.push("NO_OBSERVABLE_OPERATIONAL_EVENTS");
    operatorAdvice.push("Do not infer lack of risk from absent events.");
  }
  const urgency = snapshot.sourceIntegrity === "CONFLICT" ||
    snapshot.handoffSummary.pastExplicitDueAt > 0 ? "CRITICAL" :
    snapshot.handoffSummary.staleUnassigned > 0 ||
    snapshot.totals.overdue > 0 ? "HIGH" :
    snapshot.completeness === "UNKNOWN" ? "UNKNOWN" : "ROUTINE";
  return {
    urgency, incompleteSources, activeWork: active.length,
    blockedWork: blocked.length,
    actionsNeedingReview: snapshot.totals.partial +
      snapshot.totals.unknown,
    longestUnacceptedMinutes, latestEventAgeMinutes,
    reasons, operatorAdvice, providerOutcome: "UNKNOWN",
  };
}
export function compareOperationalSlaSnapshots(
  before: OperationalSlaSnapshot, after: OperationalSlaSnapshot,
) {
  for (const s of [before, after]) {
    if (s.digest !== slaDigest({ ...s, digest: undefined }))
      reject("SLA_SNAPSHOT_DIGEST_INVALID");
  }
  if (before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId ||
      before.policy.policyId !== after.policy.policyId)
    reject("SLA_COMPARISON_SCOPE_CHANGED");
  if (after.asOf < before.asOf)
    reject("SLA_COMPARISON_TIME_REGRESSION");
  const delta = (k: keyof OperationalSlaSnapshot["totals"]) =>
    after.totals[k] - before.totals[k];
  return {
    schema: "cyberpilot.incident.operational-sla.compare.v1" as const,
    beforeDigest: before.digest, afterDigest: after.digest,
    elapsedMinutes: elapsed(after.asOf, before.asOf),
    newOverdue: delta("overdue"),
    newUnknown: delta("unknown"),
    newObserved: delta("observed"),
    newPartial: delta("partial"),
    newDueSoon: delta("dueSoon"),
    sourceCoverageRegressed: before.sourceIntegrity === "VERIFIED" &&
      after.sourceIntegrity !== "VERIFIED",
    externalOutcomeCanBeInferred: false as const,
    externalActions: 0 as const,
  };
}
export function buildSlaOperationalPriorityQueue(
  snapshot: OperationalSlaSnapshot, max = 100,
) {
  if (snapshot.digest !== slaDigest({ ...snapshot, digest: undefined }))
    reject("SLA_SNAPSHOT_DIGEST_INVALID");
  if (!Number.isSafeInteger(max) || max < 1 || max > 500)
    reject("SLA_QUEUE_LIMIT_INVALID");
  const severity = (s: SlaDisposition) => s === "OVERDUE" ? 4 :
    s === "INDETERMINATE" ? 3 : s === "DUE_SOON" ? 2 :
    s === "ON_TIME" ? 1 : 0;
  return [...snapshot.measurements]
    .filter(x => x.completedAt === null)
    .sort((a, b) => severity(b.disposition) - severity(a.disposition) ||
      (a.dueAt ?? "9999").localeCompare(b.dueAt ?? "9999") ||
      a.metricId.localeCompare(b.metricId)).slice(0, max).map((x, i) => ({
      rank: i + 1,
      metricId: x.metricId, subjectId: x.subjectId, source: x.source,
      disposition: x.disposition, outcome: x.outcome,
      dueAt: x.dueAt, remainingMinutes: x.remainingMinutes,
      action: x.disposition === "OVERDUE" ? "REVIEW_INTERNAL_BREACH" :
        x.disposition === "INDETERMINATE" ? "REQUEST_EVIDENCE" :
        x.disposition === "DUE_SOON" ? "REVIEW_UPCOMING_DEADLINE" :
        "MONITOR_INTERNAL_PROGRESS",
      providerWriteAuthorized: false as const,
    }));
}
export function summarizeSlaByPriority(
  handoffs: HandoffSlaEvidence[], snapshot: OperationalSlaSnapshot,
) {
  if (snapshot.digest !== slaDigest({ ...snapshot, digest: undefined }))
    reject("SLA_SNAPSHOT_DIGEST_INVALID");
  return priorities.map(priority => {
    const items = handoffs.filter(x => x.priority === priority);
    const overdue = items.filter(x =>
      x.acceptedAt === null && x.dueAt < snapshot.asOf);
    const assigned = items.filter(x => x.assignedUserId !== null);
    const delays = items.map(x =>
      elapsed(x.acceptedAt ?? snapshot.asOf, x.createdAt))
      .filter((x): x is number => x !== null).sort((a, b) => a - b);
    const p50 = delays.length ? delays[Math.floor((delays.length - 1) * .5)] :
      null;
    const p95 = delays.length ? delays[Math.floor((delays.length - 1) * .95)] :
      null;
    return {
      priority, total: items.length, assigned: assigned.length,
      unassigned: items.length - assigned.length,
      overdue: overdue.length,
      accepted: items.filter(x => x.acceptedAt !== null).length,
      p50InternalAgeMinutes: p50, p95InternalAgeMinutes: p95,
      providerWrites: 0 as const,
    };
  });
}
export function operationalSlaAuditEnvelope(snapshot: OperationalSlaSnapshot) {
  if (snapshot.digest !== slaDigest({ ...snapshot, digest: undefined }))
    reject("SLA_SNAPSHOT_DIGEST_INVALID");
  return {
    schema: "cyberpilot.incident.operational-sla.audit-export.v1" as const,
    organizationId: snapshot.organizationId,
    incidentId: snapshot.incidentId, asOf: snapshot.asOf,
    policyDigest: slaDigest(snapshot.policy),
    sourceIntegrity: snapshot.sourceIntegrity,
    completeness: snapshot.completeness,
    measurementsDigest: slaDigest(snapshot.measurements),
    sourceCoverageDigest: slaDigest(snapshot.sourceCoverage),
    snapshotDigest: snapshot.digest,
    externalActions: 0 as const,
    independentProviderEvidence: false as const,
  };
}
