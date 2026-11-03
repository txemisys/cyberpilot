import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationCandidate,
  IntegrityRemediationPlan,
  IntegrityRemediationPriority,
} from "./work-integrity-remediation-plan";
import type {
  IntegrityRemediationDecisionRecord,
} from "./work-integrity-remediation-workspace";

export type IntegrityRemediationSlaClock = "CALENDAR" | "BUSINESS";
export type IntegrityRemediationSlaRule = {
  priority: IntegrityRemediationPriority;
  responseHours: number;
  resolutionHours: number;
  escalationHours: number;
};
export type IntegrityRemediationSlaPolicy = {
  schemaVersion: 1;
  clock: IntegrityRemediationSlaClock;
  timezoneOffsetMinutes: number;
  businessDayStartHour: number;
  businessDayEndHour: number;
  businessDays: number[];
  holidays: string[];
  rules: IntegrityRemediationSlaRule[];
  pauseOnDeferral: boolean;
  pauseOnRejection: boolean;
};
export type IntegrityRemediationSlaStatus =
  | "RESOLVED" | "ON_TIME" | "RESPONSE_OVERDUE"
  | "RESOLUTION_OVERDUE" | "ESCALATION_OVERDUE"
  | "DEFERRED" | "REJECTED";
export type IntegrityRemediationSlaEntry = {
  candidateId: string;
  caseKey: string | null;
  workItemId: string | null;
  action: IntegrityRemediationCandidate["action"];
  priority: IntegrityRemediationPriority;
  createdAt: string;
  evaluatedAt: string;
  responseDueAt: string;
  resolutionDueAt: string;
  escalationDueAt: string;
  responseAt: string | null;
  resolutionAt: string | null;
  decision: IntegrityRemediationDecisionRecord["decision"] | null;
  status: IntegrityRemediationSlaStatus;
  responseOverdueMinutes: number;
  resolutionOverdueMinutes: number;
  escalationOverdueMinutes: number;
  remainingResolutionMinutes: number;
  riskPoints: number;
};
export type IntegrityRemediationSlaReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  clock: IntegrityRemediationSlaClock;
  entries: IntegrityRemediationSlaEntry[];
  totals: {
    candidates: number;
    resolved: number;
    onTime: number;
    responseOverdue: number;
    resolutionOverdue: number;
    escalationOverdue: number;
    deferred: number;
    rejected: number;
    atRisk: number;
    overdueRiskPoints: number;
    meanRemainingMinutes: number;
    responseCompliance: number;
    resolutionCompliance: number;
  };
  byPriority: Record<IntegrityRemediationPriority, {
    total: number;
    overdue: number;
    resolved: number;
    riskPoints: number;
  }>;
};
export type IntegrityRemediationSlaQuery = {
  priorities?: IntegrityRemediationPriority[];
  statuses?: IntegrityRemediationSlaStatus[];
  caseKeys?: string[];
  workItemIds?: string[];
  overdueOnly?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityRemediationSlaPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  entries: IntegrityRemediationSlaEntry[];
};
const priorities: IntegrityRemediationPriority[] = ["P0", "P1", "P2", "P3"];
const statuses: IntegrityRemediationSlaStatus[] = [
  "RESOLVED", "ON_TIME", "RESPONSE_OVERDUE", "RESOLUTION_OVERDUE",
  "ESCALATION_OVERDUE", "DEFERRED", "REJECTED",
];
const hour = 3600000;
const minute = 60000;
const day = 86400000;
function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function finiteInt(value: unknown, label: string, min: number, max: number) {
  if (!Number.isSafeInteger(value) || (value as number) < min ||
      (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
function timestamp(value: unknown, label: string): string {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function strings(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || x.length < 1 ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
export function parseIntegrityRemediationSlaPolicy(
  value: unknown,
): IntegrityRemediationSlaPolicy {
  const raw = record(value, "remediation SLA policy");
  if (Object.keys(raw).some(x => ![
    "schemaVersion", "clock", "timezoneOffsetMinutes",
    "businessDayStartHour", "businessDayEndHour", "businessDays",
    "holidays", "rules", "pauseOnDeferral", "pauseOnRejection",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown SLA policy field.");
  if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1)
    throw new WorkInputError("INVALID", "Unsupported SLA policy version.");
  const clock = raw.clock ?? "CALENDAR";
  if (clock !== "CALENDAR" && clock !== "BUSINESS")
    throw new WorkInputError("INVALID", "Invalid SLA clock.");
  const timezoneOffsetMinutes = finiteInt(
    raw.timezoneOffsetMinutes ?? 0, "timezone offset", -840, 840);
  const businessDayStartHour = finiteInt(
    raw.businessDayStartHour ?? 9, "business start hour", 0, 23);
  const businessDayEndHour = finiteInt(
    raw.businessDayEndHour ?? 17, "business end hour", 1, 24);
  if (businessDayEndHour <= businessDayStartHour)
    throw new WorkInputError("INVALID", "Business hours must increase.");
  const days = raw.businessDays ?? [1, 2, 3, 4, 5];
  if (!Array.isArray(days) || days.length < 1 || days.length > 7)
    throw new WorkInputError("INVALID", "Invalid business days.");
  const businessDays = [...new Set(days.map(x =>
    finiteInt(x, "business day", 0, 6)))].sort((a, b) => a - b);
  const holidays = strings(raw.holidays ?? [], "SLA holidays", 366);
  for (const holiday of holidays) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(holiday) ||
        !Number.isFinite(Date.parse(holiday + "T00:00:00.000Z")) ||
        new Date(holiday + "T00:00:00.000Z")
          .toISOString().slice(0, 10) !== holiday)
      throw new WorkInputError("INVALID", "Invalid SLA holiday.");
  }
  if (!Array.isArray(raw.rules) || raw.rules.length !== 4)
    throw new WorkInputError("INVALID", "Four SLA priority rules required.");
  const seen = new Set<string>();
  const rules: IntegrityRemediationSlaRule[] = [];
  for (const entry of raw.rules) {
    const rule = record(entry, "SLA rule");
    if (Object.keys(rule).some(x => ![
      "priority", "responseHours", "resolutionHours", "escalationHours",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown SLA rule field.");
    if (!priorities.includes(rule.priority as IntegrityRemediationPriority) ||
        seen.has(rule.priority as string))
      throw new WorkInputError("INVALID", "Duplicate or invalid SLA priority.");
    seen.add(rule.priority as string);
    const responseHours = finiteInt(rule.responseHours, "response hours", 1, 87600);
    const resolutionHours = finiteInt(
      rule.resolutionHours, "resolution hours", 1, 87600);
    const escalationHours = finiteInt(
      rule.escalationHours, "escalation hours", 1, 87600);
    if (responseHours > resolutionHours ||
        escalationHours < responseHours)
      throw new WorkInputError("INVALID", "Inconsistent SLA deadlines.");
    rules.push({
      priority: rule.priority as IntegrityRemediationPriority,
      responseHours, resolutionHours, escalationHours,
    });
  }
  for (const flag of ["pauseOnDeferral", "pauseOnRejection"]) {
    if (raw[flag] !== undefined && typeof raw[flag] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid SLA pause flag.");
  }
  return {
    schemaVersion: 1, clock, timezoneOffsetMinutes,
    businessDayStartHour, businessDayEndHour,
    businessDays, holidays: holidays.sort(),
    rules: rules.sort((a, b) =>
      priorities.indexOf(a.priority) - priorities.indexOf(b.priority)),
    pauseOnDeferral: raw.pauseOnDeferral === true,
    pauseOnRejection: raw.pauseOnRejection === true,
  };
}
function localDay(ms: number, policy: IntegrityRemediationSlaPolicy) {
  const adjusted = ms + policy.timezoneOffsetMinutes * minute;
  const d = new Date(adjusted);
  return {
    year: d.getUTCFullYear(), month: d.getUTCMonth(),
    date: d.getUTCDate(), weekday: d.getUTCDay(),
    hour: d.getUTCHours(), minute: d.getUTCMinutes(),
    dayStart: Math.floor(adjusted / day) * day -
      policy.timezoneOffsetMinutes * minute,
    dateKey: d.toISOString().slice(0, 10),
  };
}
function workingDay(ms: number, policy: IntegrityRemediationSlaPolicy) {
  const local = localDay(ms, policy);
  return policy.businessDays.includes(local.weekday) &&
    !policy.holidays.includes(local.dateKey);
}
function workingWindow(ms: number, policy: IntegrityRemediationSlaPolicy) {
  const local = localDay(ms, policy);
  return {
    start: local.dayStart + policy.businessDayStartHour * hour,
    end: local.dayStart + policy.businessDayEndHour * hour,
  };
}
export function addIntegritySlaHours(
  start: string, hours: number, policy: IntegrityRemediationSlaPolicy,
): string {
  timestamp(start, "SLA start");
  if (!Number.isSafeInteger(hours) || hours < 0 || hours > 87600)
    throw new WorkInputError("INVALID", "Invalid SLA duration.");
  if (policy.clock === "CALENDAR")
    return new Date(Date.parse(start) + hours * hour).toISOString();
  let current = Date.parse(start);
  let remaining = hours * hour;
  let iterations = 0;
  while (remaining > 0) {
    if (++iterations > 20000)
      throw new WorkInputError("INVALID", "SLA business calendar exhausted.");
    const window = workingWindow(current, policy);
    if (!workingDay(current, policy) || current >= window.end) {
      current = window.start + day;
      continue;
    }
    if (current < window.start) current = window.start;
    const available = window.end - current;
    const consumed = Math.min(available, remaining);
    current += consumed;
    remaining -= consumed;
  }
  return new Date(current).toISOString();
}
export function countIntegritySlaMinutes(
  from: string, to: string, policy: IntegrityRemediationSlaPolicy,
): number {
  timestamp(from, "SLA interval start");
  timestamp(to, "SLA interval end");
  const a = Date.parse(from);
  const b = Date.parse(to);
  if (a === b) return 0;
  if (a > b) return -countIntegritySlaMinutes(to, from, policy);
  if (policy.clock === "CALENDAR") return Math.floor((b - a) / minute);
  let total = 0;
  let current = a;
  let iterations = 0;
  while (current < b) {
    if (++iterations > 20000)
      throw new WorkInputError("INVALID", "SLA interval too long.");
    const window = workingWindow(current, policy);
    const next = Math.min(b, window.start + day);
    if (workingDay(current, policy)) {
      const begin = Math.max(current, window.start);
      const end = Math.min(next, window.end);
      if (end > begin) total += end - begin;
    }
    current = next;
  }
  return Math.floor(total / minute);
}
function decideStatus(
  item: IntegrityRemediationCandidate,
  decision: IntegrityRemediationDecisionRecord | undefined,
  now: string,
  responseDueAt: string,
  resolutionDueAt: string,
  escalationDueAt: string,
  policy: IntegrityRemediationSlaPolicy,
): IntegrityRemediationSlaStatus {
  if (decision?.decision === "REJECT" && policy.pauseOnRejection)
    return "REJECTED";
  if (decision?.decision === "DEFER" && policy.pauseOnDeferral)
    return "DEFERRED";
  // Accepting a proposed action is not evidence that the work was completed.
  // Resolution must be established from a subsequent evidence snapshot.
  if (now > escalationDueAt) return "ESCALATION_OVERDUE";
  if (now > resolutionDueAt) return "RESOLUTION_OVERDUE";
  if (!decision && now > responseDueAt) return "RESPONSE_OVERDUE";
  return "ON_TIME";
}
function overdue(now: string, due: string, policy: IntegrityRemediationSlaPolicy) {
  return now > due ? countIntegritySlaMinutes(due, now, policy) : 0;
}
function entry(
  item: IntegrityRemediationCandidate,
  decision: IntegrityRemediationDecisionRecord | undefined,
  createdAt: string,
  now: string,
  rule: IntegrityRemediationSlaRule,
  policy: IntegrityRemediationSlaPolicy,
): IntegrityRemediationSlaEntry {
  const responseDueAt = addIntegritySlaHours(createdAt, rule.responseHours, policy);
  const resolutionDueAt = addIntegritySlaHours(
    createdAt, rule.resolutionHours, policy);
  const escalationDueAt = addIntegritySlaHours(
    createdAt, rule.escalationHours, policy);
  const status = decideStatus(
    item, decision, now, responseDueAt, resolutionDueAt,
    escalationDueAt, policy);
  const responseAt = decision?.reviewedAt ?? null;
  const resolutionAt = status === "RESOLVED" ? responseAt : null;
  return {
    candidateId: item.id, caseKey: item.caseKey,
    workItemId: item.workItemId, action: item.action,
    priority: item.priority, createdAt, evaluatedAt: now,
    responseDueAt, resolutionDueAt, escalationDueAt,
    responseAt, resolutionAt, decision: decision?.decision ?? null,
    status,
    responseOverdueMinutes: responseAt
      ? overdue(responseAt, responseDueAt, policy)
      : overdue(now, responseDueAt, policy),
    resolutionOverdueMinutes: resolutionAt
      ? overdue(resolutionAt, resolutionDueAt, policy)
      : overdue(now, resolutionDueAt, policy),
    escalationOverdueMinutes: overdue(now, escalationDueAt, policy),
    remainingResolutionMinutes: Math.max(0,
      countIntegritySlaMinutes(now, resolutionDueAt, policy)),
    riskPoints: item.estimatedRiskReduction,
  };
}
export function evaluateIntegrityRemediationSla(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
  createdAt: string,
  evaluatedAt: string,
  policy: IntegrityRemediationSlaPolicy,
): IntegrityRemediationSlaReport {
  timestamp(createdAt, "SLA created at");
  timestamp(evaluatedAt, "SLA evaluated at");
  if (evaluatedAt < createdAt)
    throw new WorkInputError("INVALID", "SLA evaluation precedes creation.");
  const decisionMap = new Map(decisions.map(x => [x.candidateId, x]));
  const entries = plan.candidates.map(item => {
    const rule = policy.rules.find(x => x.priority === item.priority);
    if (!rule) throw new WorkInputError("INVALID", "Missing SLA priority rule.");
    return entry(item, decisionMap.get(item.id),
      createdAt, evaluatedAt, rule, policy);
  });
  const byPriority = Object.fromEntries(priorities.map(priority => {
    const rows = entries.filter(x => x.priority === priority);
    return [priority, {
      total: rows.length,
      overdue: rows.filter(x =>
        x.responseOverdueMinutes > 0 || x.resolutionOverdueMinutes > 0).length,
      resolved: rows.filter(x => x.status === "RESOLVED").length,
      riskPoints: rows.reduce((sum, x) => sum + x.riskPoints, 0),
    }];
  })) as IntegrityRemediationSlaReport["byPriority"];
  const responseCompliant = entries.filter(x =>
    x.responseOverdueMinutes === 0).length;
  const resolutionCompliant = entries.filter(x =>
    x.resolutionOverdueMinutes === 0).length;
  const overdueEntries = entries.filter(x =>
    x.responseOverdueMinutes > 0 || x.resolutionOverdueMinutes > 0);
  return {
    schemaVersion: 1, captureId: plan.captureId,
    evaluatedAt, clock: policy.clock, entries,
    byPriority,
    totals: {
      candidates: entries.length,
      resolved: entries.filter(x => x.status === "RESOLVED").length,
      onTime: entries.filter(x => x.status === "ON_TIME").length,
      responseOverdue: entries.filter(x =>
        x.responseOverdueMinutes > 0).length,
      resolutionOverdue: entries.filter(x =>
        x.resolutionOverdueMinutes > 0).length,
      escalationOverdue: entries.filter(x =>
        x.escalationOverdueMinutes > 0).length,
      deferred: entries.filter(x => x.status === "DEFERRED").length,
      rejected: entries.filter(x => x.status === "REJECTED").length,
      atRisk: entries.filter(x => x.remainingResolutionMinutes <= 120 &&
        x.status !== "RESOLVED").length,
      overdueRiskPoints: overdueEntries.reduce((sum, x) =>
        sum + x.riskPoints, 0),
      meanRemainingMinutes: entries.length
        ? entries.reduce((sum, x) =>
          sum + x.remainingResolutionMinutes, 0) / entries.length : 0,
      responseCompliance: entries.length
        ? responseCompliant / entries.length : 1,
      resolutionCompliance: entries.length
        ? resolutionCompliant / entries.length : 1,
    },
  };
}
export function parseIntegrityRemediationSlaQuery(
  value: unknown,
): IntegrityRemediationSlaQuery {
  const raw = record(value, "SLA query");
  if (Object.keys(raw).some(x => ![
    "priorities", "statuses", "caseKeys", "workItemIds",
    "overdueOnly", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown SLA query field.");
  if (raw.overdueOnly !== undefined && typeof raw.overdueOnly !== "boolean")
    throw new WorkInputError("INVALID", "Invalid overdue filter.");
  const selectedPriorities = raw.priorities === undefined
    ? undefined : strings(raw.priorities, "SLA priorities", 4);
  const selectedStatuses = raw.statuses === undefined
    ? undefined : strings(raw.statuses, "SLA statuses", 7);
  if (selectedPriorities?.some(x =>
    !priorities.includes(x as IntegrityRemediationPriority)) ||
    selectedStatuses?.some(x => !statuses.includes(x as IntegrityRemediationSlaStatus)))
    throw new WorkInputError("INVALID", "Unknown SLA filter value.");
  return {
    ...(selectedPriorities !== undefined ? {
      priorities: selectedPriorities as IntegrityRemediationPriority[],
    } : {}),
    ...(selectedStatuses !== undefined ? {
      statuses: selectedStatuses as IntegrityRemediationSlaStatus[],
    } : {}),
    ...(raw.caseKeys !== undefined ? {
      caseKeys: strings(raw.caseKeys, "SLA cases", 1000),
    } : {}),
    ...(raw.workItemIds !== undefined ? {
      workItemIds: strings(raw.workItemIds, "SLA work items", 1000),
    } : {}),
    overdueOnly: raw.overdueOnly === true,
    offset: raw.offset === undefined ? 0 :
      finiteInt(raw.offset, "SLA offset", 0, 1000000),
    limit: raw.limit === undefined ? 100 :
      finiteInt(raw.limit, "SLA limit", 1, 1000),
  };
}
export function queryIntegrityRemediationSla(
  report: IntegrityRemediationSlaReport,
  query: IntegrityRemediationSlaQuery,
): IntegrityRemediationSlaPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid SLA pagination.");
  const selected = report.entries.filter(item =>
    (!query.priorities || query.priorities.includes(item.priority)) &&
    (!query.statuses || query.statuses.includes(item.status)) &&
    (!query.caseKeys || (item.caseKey !== null &&
      query.caseKeys.includes(item.caseKey))) &&
    (!query.workItemIds || (item.workItemId !== null &&
      query.workItemIds.includes(item.workItemId))) &&
    (!query.overdueOnly || item.responseOverdueMinutes > 0 ||
      item.resolutionOverdueMinutes > 0));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    entries: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityRemediationSla(
  before: IntegrityRemediationSlaReport,
  after: IntegrityRemediationSlaReport,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "SLA captures differ.");
  const previous = new Map(before.entries.map(x => [x.candidateId, x]));
  const current = new Map(after.entries.map(x => [x.candidateId, x]));
  const introduced = after.entries.filter(x =>
    !previous.has(x.candidateId)).map(x => x.candidateId);
  const removed = before.entries.filter(x =>
    !current.has(x.candidateId)).map(x => x.candidateId);
  const deteriorated: string[] = [];
  const improved: string[] = [];
  const statusChanges: {
    candidateId: string;
    from: IntegrityRemediationSlaStatus;
    to: IntegrityRemediationSlaStatus;
  }[] = [];
  for (const item of after.entries) {
    const old = previous.get(item.candidateId);
    if (!old) continue;
    if (old.status !== item.status)
      statusChanges.push({
        candidateId: item.candidateId, from: old.status, to: item.status,
      });
    const oldOverdue = old.responseOverdueMinutes +
      old.resolutionOverdueMinutes;
    const newOverdue = item.responseOverdueMinutes +
      item.resolutionOverdueMinutes;
    if (newOverdue > oldOverdue) deteriorated.push(item.candidateId);
    if (newOverdue < oldOverdue) improved.push(item.candidateId);
  }
  return {
    captureId: before.captureId,
    from: before.evaluatedAt, to: after.evaluatedAt,
    introduced: introduced.sort(), removed: removed.sort(),
    deteriorated: deteriorated.sort(), improved: improved.sort(),
    statusChanges: statusChanges.sort((a, b) =>
      a.candidateId.localeCompare(b.candidateId)),
    responseComplianceDelta: after.totals.responseCompliance -
      before.totals.responseCompliance,
    resolutionComplianceDelta: after.totals.resolutionCompliance -
      before.totals.resolutionCompliance,
    overdueRiskDelta: after.totals.overdueRiskPoints -
      before.totals.overdueRiskPoints,
  };
}
