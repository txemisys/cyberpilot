import { WorkInputError } from "./remediation-work-input";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
import type { IntegrityReviewReplay, IntegrityReviewEvent } from "./work-integrity-remediation-review-event-replay";

export type IntegrityReviewDeadlineRule = {
  severity: "ERROR" | "WARNING" | "INFO";
  acknowledgeWithinHours: number;
  resolveWithinHours: number;
  escalationAfterHours: number;
};
export type IntegrityReviewDeadlinePolicy = {
  rules: IntegrityReviewDeadlineRule[];
  evaluationTime: string;
  useBusinessHours: boolean;
  businessDayStartHour: number;
  businessDayEndHour: number;
  excludeWeekends: boolean;
  maximumTrackedTasks: number;
};
export type IntegrityReviewDeadlineTask = {
  taskId: string;
  severity: string;
  action: string;
  disposition: string;
  openedAt: string;
  firstAcknowledgedAt: string | null;
  firstStartedAt: string | null;
  completedAt: string | null;
  acknowledgmentDeadline: string;
  resolutionDeadline: string;
  escalationDeadline: string;
  acknowledgmentHours: number | null;
  resolutionHours: number | null;
  outstandingHours: number;
  acknowledgmentBreached: boolean;
  resolutionBreached: boolean;
  escalationRequired: boolean;
  acknowledgmentPending: boolean;
  resolutionPending: boolean;
  severityScore: number;
  status: "COMPLETED_ON_TIME" | "COMPLETED_LATE" |
    "ESCALATION_REQUIRED" | "OVERDUE" | "ON_TRACK";
};
export type IntegrityReviewDeadlineReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityReviewDeadlinePolicy;
  tasks: IntegrityReviewDeadlineTask[];
  totals: {
    tasks: number;
    completedOnTime: number;
    completedLate: number;
    escalationRequired: number;
    overdue: number;
    onTrack: number;
    acknowledgmentBreaches: number;
    resolutionBreaches: number;
    pendingAcknowledgments: number;
    pendingResolutions: number;
    maximumOutstandingHours: number;
    meanOutstandingHours: number;
    bySeverity: Record<string, number>;
  };
  limitation: string;
};
export type IntegrityReviewDeadlineQuery = {
  statuses?: IntegrityReviewDeadlineTask["status"][];
  severities?: string[];
  onlyBreached?: boolean;
  taskIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityReviewDeadlinePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  tasks: IntegrityReviewDeadlineTask[];
};
const severities = ["ERROR", "WARNING", "INFO"] as const;
const statuses: IntegrityReviewDeadlineTask["status"][] = [
  "COMPLETED_ON_TIME", "COMPLETED_LATE",
  "ESCALATION_REQUIRED", "OVERDUE", "ON_TRACK",
];
const defaults: Omit<IntegrityReviewDeadlinePolicy, "evaluationTime"> = {
  rules: [
    { severity: "ERROR", acknowledgeWithinHours: 4,
      resolveWithinHours: 24, escalationAfterHours: 12 },
    { severity: "WARNING", acknowledgeWithinHours: 24,
      resolveWithinHours: 72, escalationAfterHours: 48 },
    { severity: "INFO", acknowledgeWithinHours: 72,
      resolveWithinHours: 168, escalationAfterHours: 120 },
  ],
  useBusinessHours: false,
  businessDayStartHour: 9,
  businessDayEndHour: 17,
  excludeWeekends: true,
  maximumTrackedTasks: 2000,
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
function number(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isFinite(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function timestamp(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function identifiers(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
export function parseIntegrityReviewDeadlinePolicy(
  value: unknown,
  evaluationTime: string,
): IntegrityReviewDeadlinePolicy {
  const evaluated = timestamp(evaluationTime, "deadline evaluation time");
  if (value === undefined)
    return { ...defaults, rules: defaults.rules.map(x => ({ ...x })),
      evaluationTime: evaluated };
  const raw = record(value, "review deadline policy");
  if (Object.keys(raw).some(x => ![
    "rules", "evaluationTime", "useBusinessHours",
    "businessDayStartHour", "businessDayEndHour",
    "excludeWeekends", "maximumTrackedTasks",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown deadline policy field.");
  const rules = raw.rules === undefined ?
    defaults.rules.map(x => ({ ...x })) : (() => {
      if (!Array.isArray(raw.rules) || raw.rules.length !== 3)
        throw new WorkInputError("INVALID", "Three severity rules required.");
      return raw.rules.map(entry => {
        const rule = record(entry, "deadline severity rule");
        if (Object.keys(rule).some(x => ![
          "severity", "acknowledgeWithinHours",
          "resolveWithinHours", "escalationAfterHours",
        ].includes(x)) ||
            !severities.includes(rule.severity as typeof severities[number]))
          throw new WorkInputError("INVALID", "Invalid severity rule.");
        const acknowledgeWithinHours = number(rule.acknowledgeWithinHours,
          "acknowledgment deadline", 0, 8760);
        const resolveWithinHours = number(rule.resolveWithinHours,
          "resolution deadline", 0, 8760);
        const escalationAfterHours = number(rule.escalationAfterHours,
          "escalation deadline", 0, 8760);
        if (acknowledgeWithinHours > resolveWithinHours ||
            escalationAfterHours > resolveWithinHours)
          throw new WorkInputError("INVALID", "Inconsistent deadline thresholds.");
        return {
          severity: rule.severity as typeof severities[number],
          acknowledgeWithinHours, resolveWithinHours,
          escalationAfterHours,
        };
      });
    })();
  if (new Set(rules.map(x => x.severity)).size !== 3)
    throw new WorkInputError("INVALID", "Duplicate deadline severity.");
  for (const key of ["useBusinessHours", "excludeWeekends"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid deadline boolean.");
  }
  const start = integer(raw.businessDayStartHour ??
    defaults.businessDayStartHour, "business start hour", 0, 23);
  const end = integer(raw.businessDayEndHour ??
    defaults.businessDayEndHour, "business end hour", 1, 24);
  if (end <= start)
    throw new WorkInputError("INVALID", "Business day end must follow start.");
  return {
    rules,
    evaluationTime: raw.evaluationTime === undefined ?
      evaluated : timestamp(raw.evaluationTime, "deadline evaluation time"),
    useBusinessHours: raw.useBusinessHours === true,
    businessDayStartHour: start,
    businessDayEndHour: end,
    excludeWeekends: raw.excludeWeekends === undefined ?
      defaults.excludeWeekends : raw.excludeWeekends as boolean,
    maximumTrackedTasks: integer(raw.maximumTrackedTasks ??
      defaults.maximumTrackedTasks, "maximum deadline tasks", 1, 5000),
  };
}
const hour = 3600000;
function eligibleHour(date: Date, policy: IntegrityReviewDeadlinePolicy) {
  if (policy.excludeWeekends && (date.getUTCDay() === 0 ||
      date.getUTCDay() === 6)) return false;
  return date.getUTCHours() >= policy.businessDayStartHour &&
    date.getUTCHours() < policy.businessDayEndHour;
}
function advance(start: number, hours: number,
  policy: IntegrityReviewDeadlinePolicy): number {
  if (!policy.useBusinessHours) return start + hours * hour;
  if (hours === 0) return start;
  let remaining = hours;
  let current = start;
  // Advance to the next whole UTC hour boundary, counting only eligible
  // portions of each hour. A bounded iteration prevents runaway schedules.
  for (let iterations = 0; iterations < 250000 &&
      remaining > 0; iterations++) {
    const next = Math.floor(current / hour) * hour + hour;
    const step = (next - current) / hour;
    if (eligibleHour(new Date(current), policy))
      remaining -= step;
    current = next;
    if (remaining < 0)
      current += remaining * hour;
  }
  if (remaining > 0)
    throw new WorkInputError("INVALID", "Deadline exceeds business-hour horizon.");
  return current;
}
function elapsed(start: number, end: number,
  policy: IntegrityReviewDeadlinePolicy): number {
  if (end <= start) return 0;
  if (!policy.useBusinessHours) return (end - start) / hour;
  let current = start;
  let hours = 0;
  for (let iterations = 0; iterations < 250000 &&
      current < end; iterations++) {
    const next = Math.min(end, Math.floor(current / hour) * hour + hour);
    if (eligibleHour(new Date(current), policy))
      hours += (next - current) / hour;
    current = next;
  }
  if (current < end)
    throw new WorkInputError("INVALID", "Business-hour interval too long.");
  return hours;
}
function round(value: number) { return Math.round(value * 100) / 100; }
export function evaluateIntegrityReviewDeadlines(
  queue: IntegrityCapacityReviewQueue,
  replay: IntegrityReviewReplay,
  events: readonly IntegrityReviewEvent[],
  policy: IntegrityReviewDeadlinePolicy,
): IntegrityReviewDeadlineReport {
  if (queue.captureId !== replay.captureId)
    throw new WorkInputError("INVALID", "Review deadline capture mismatch.");
  if (queue.tasks.length > policy.maximumTrackedTasks)
    throw new WorkInputError("INVALID", "Deadline task limit exceeded.");
  const states = new Map(replay.tasks.map(x => [x.taskId, x]));
  const accepted = new Set(replay.results.filter(x =>
    x.accepted).map(x => x.eventId));
  const now = Date.parse(policy.evaluationTime);
  const openedAt = Date.parse(queue.evaluatedAt);
  if (now < openedAt)
    throw new WorkInputError("INVALID", "Deadline evaluation precedes capture.");
  const tasks = queue.tasks.map(task => {
    const state = states.get(task.taskId);
    if (!state)
      throw new WorkInputError("INVALID", "Missing review deadline task state.");
    const relevant = events.filter(x => x.taskId === task.taskId &&
      accepted.has(x.eventId)).sort((a, b) =>
        Date.parse(a.occurredAt) - Date.parse(b.occurredAt));
    const first = (kind: IntegrityReviewEvent["kind"]) =>
      relevant.find(x => x.kind === kind)?.occurredAt ?? null;
    const firstAcknowledgedAt = first("ACKNOWLEDGE");
    const firstStartedAt = first("START_REVIEW");
    const completion = [...relevant].reverse().find(x =>
      x.kind === "RESOLVE" || x.kind === "WAIVE");
    const completedAt = state.terminal ?
      completion?.occurredAt ?? null : null;
    const rule = policy.rules.find(x => x.severity === task.severity);
    if (!rule)
      throw new WorkInputError("INVALID", "Missing deadline severity rule.");
    const acknowledgmentDeadline = advance(openedAt,
      rule.acknowledgeWithinHours, policy);
    const resolutionDeadline = advance(openedAt,
      rule.resolveWithinHours, policy);
    const escalationDeadline = advance(openedAt,
      rule.escalationAfterHours, policy);
    const firstAckTime = firstAcknowledgedAt === null ?
      null : Date.parse(firstAcknowledgedAt);
    const completionTime = completedAt === null ?
      null : Date.parse(completedAt);
    const acknowledgmentBreached = firstAckTime === null ?
      now > acknowledgmentDeadline :
      firstAckTime > acknowledgmentDeadline;
    const resolutionBreached = completionTime === null ?
      now > resolutionDeadline :
      completionTime > resolutionDeadline;
    const escalationRequired = !state.terminal &&
      now > escalationDeadline;
    const status: IntegrityReviewDeadlineTask["status"] =
      state.terminal ?
        (acknowledgmentBreached || resolutionBreached ?
          "COMPLETED_LATE" : "COMPLETED_ON_TIME") :
      escalationRequired ? "ESCALATION_REQUIRED" :
      resolutionBreached || acknowledgmentBreached ?
        "OVERDUE" : "ON_TRACK";
    const severityScore = task.severity === "ERROR" ? 300 :
      task.severity === "WARNING" ? 200 : 100;
    return {
      taskId: task.taskId, severity: task.severity,
      action: task.action, disposition: state.disposition,
      openedAt: queue.evaluatedAt, firstAcknowledgedAt,
      firstStartedAt, completedAt,
      acknowledgmentDeadline: new Date(acknowledgmentDeadline).toISOString(),
      resolutionDeadline: new Date(resolutionDeadline).toISOString(),
      escalationDeadline: new Date(escalationDeadline).toISOString(),
      acknowledgmentHours: firstAckTime === null ? null :
        round(elapsed(openedAt, firstAckTime, policy)),
      resolutionHours: completionTime === null ? null :
        round(elapsed(openedAt, completionTime, policy)),
      outstandingHours: round(elapsed(openedAt,
        completionTime ?? now, policy)),
      acknowledgmentBreached, resolutionBreached,
      escalationRequired,
      acknowledgmentPending: firstAckTime === null,
      resolutionPending: !state.terminal,
      severityScore, status,
    };
  });
  tasks.sort((a, b) =>
    Number(b.escalationRequired) - Number(a.escalationRequired) ||
    Number(b.resolutionBreached) - Number(a.resolutionBreached) ||
    b.severityScore - a.severityScore ||
    b.outstandingHours - a.outstandingHours ||
    a.taskId.localeCompare(b.taskId));
  const count = (status: IntegrityReviewDeadlineTask["status"]) =>
    tasks.filter(x => x.status === status).length;
  const bySeverity: Record<string, number> = {};
  for (const task of tasks)
    bySeverity[task.severity] = (bySeverity[task.severity] ?? 0) + 1;
  return {
    schemaVersion: 1, captureId: queue.captureId,
    evaluatedAt: policy.evaluationTime, policy, tasks,
    totals: {
      tasks: tasks.length,
      completedOnTime: count("COMPLETED_ON_TIME"),
      completedLate: count("COMPLETED_LATE"),
      escalationRequired: count("ESCALATION_REQUIRED"),
      overdue: count("OVERDUE"), onTrack: count("ON_TRACK"),
      acknowledgmentBreaches: tasks.filter(x =>
        x.acknowledgmentBreached).length,
      resolutionBreaches: tasks.filter(x =>
        x.resolutionBreached).length,
      pendingAcknowledgments: tasks.filter(x =>
        x.acknowledgmentPending).length,
      pendingResolutions: tasks.filter(x =>
        x.resolutionPending).length,
      maximumOutstandingHours: Math.max(0, ...tasks.map(x =>
        x.outstandingHours)),
      meanOutstandingHours: tasks.length ? round(tasks.reduce((a, x) =>
        a + x.outstandingHours, 0) / tasks.length) : 0,
      bySeverity,
    },
    limitation: "Deadlines are calculated from the supplied capture time and caller-provided events. UTC business-hour rules do not model local holidays or authenticate review activity.",
  };
}
export function parseIntegrityReviewDeadlineQuery(
  value: unknown,
): IntegrityReviewDeadlineQuery {
  const raw = record(value, "deadline query");
  if (Object.keys(raw).some(x => ![
    "statuses", "severities", "onlyBreached",
    "taskIds", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown deadline query field.");
  const selectedStatuses = raw.statuses === undefined ? undefined :
    identifiers(raw.statuses, "deadline statuses", statuses.length);
  const selectedSeverities = raw.severities === undefined ? undefined :
    identifiers(raw.severities, "deadline severities", severities.length);
  if (selectedStatuses?.some(x => !statuses.includes(
    x as IntegrityReviewDeadlineTask["status"])) ||
      selectedSeverities?.some(x => !severities.includes(
        x as typeof severities[number])))
    throw new WorkInputError("INVALID", "Unknown deadline filter.");
  if (raw.onlyBreached !== undefined &&
      typeof raw.onlyBreached !== "boolean")
    throw new WorkInputError("INVALID", "Invalid deadline breach filter.");
  return {
    ...(selectedStatuses === undefined ? {} : {
      statuses: selectedStatuses as IntegrityReviewDeadlineTask["status"][],
    }),
    ...(selectedSeverities === undefined ? {} : {
      severities: selectedSeverities,
    }),
    ...(raw.taskIds === undefined ? {} : {
      taskIds: identifiers(raw.taskIds, "deadline task IDs", 500),
    }),
    onlyBreached: raw.onlyBreached === true,
    offset: integer(raw.offset ?? 0, "deadline offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "deadline limit", 1, 500),
  };
}
export function queryIntegrityReviewDeadlines(
  report: IntegrityReviewDeadlineReport,
  query: IntegrityReviewDeadlineQuery,
): IntegrityReviewDeadlinePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.tasks.filter(x =>
    (!query.statuses || query.statuses.includes(x.status)) &&
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.taskIds || query.taskIds.includes(x.taskId)) &&
    (!query.onlyBreached ||
      x.acknowledgmentBreached || x.resolutionBreached));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    tasks: selected.slice(offset, offset + limit),
  };
}
