import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

export type CohortQuery = {
  captureId?: string;
  from: Date;
  to: Date;
  limit: number;
  offset: number;
  includeEmpty: boolean;
  order: "RECENT" | "OLDEST" | "MOST_OPEN" | "MOST_OVERDUE";
  overdueHours: number;
};
export type CohortCapture = {
  id: string;
  createdAt: Date;
};
export type CohortTask = {
  id: string;
  captureId: string;
  severity: string;
  disposition: string;
  createdAt: Date;
  completedAt: Date | null;
  ownerUserId: string | null;
  required: boolean;
};
export type CohortEscalation = {
  id: string;
  taskId: string;
  state: string;
  level: number;
  openedAt: Date;
  acknowledgedAt: Date | null;
  resolvedAt: Date | null;
};
export type CohortNotification = {
  id: string;
  taskId: string;
  kind: string;
  createdAt: Date;
  readAt: Date | null;
  dismissedAt: Date | null;
};
export type CohortProvider = {
  id: string;
  taskId: string;
  outcome: string;
  checkedAt: Date;
};
export type CohortRow = {
  captureId: string;
  createdAt: string;
  totalTasks: number;
  open: number;
  inReview: number;
  resolved: number;
  waived: number;
  overdue: number;
  unassigned: number;
  requiredOpen: number;
  severity: Record<string, number>;
  activeEscalations: number;
  acknowledgedEscalations: number;
  closedEscalations: number;
  highestEscalationLevel: number;
  notifications: number;
  unread: number;
  dismissed: number;
  providerCheckedTasks: number;
  providerFailingTasks: number;
  providerPassedTasks: number;
  providerUnknownTasks: number;
  providerLastCheckedAt: string | null;
  oldestOpenAt: string | null;
  longestOpenHours: number;
  medianOpenHours: number;
  coverage: {
    activeOwnerPercent: number;
    providerCheckedPercent: number;
    closedPercent: number;
  };
  anomalies: string[];
  digest: string;
};
export type CohortTotals = {
  captures: number;
  tasks: number;
  open: number;
  resolved: number;
  waived: number;
  overdue: number;
  unassigned: number;
  activeEscalations: number;
  unread: number;
  providerFailingTasks: number;
  providerUnknownTasks: number;
};
export type CohortReport = {
  schema: "cyberpilot.integrity.capture.cohorts.v1";
  organizationId: string;
  generatedAt: string;
  from: string;
  to: string;
  offset: number;
  limit: number;
  totalCaptures: number;
  hasMore: boolean;
  complete: boolean;
  order: CohortQuery["order"];
  rows: CohortRow[];
  totalsOnPage: CohortTotals;
  digest: string;
  limitations: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected capture cohort query.");
  return value as Record<string, unknown>;
}
function number(value: unknown, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid cohort integer.");
  return value;
}
function date(value: unknown) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    throw new WorkInputError("INVALID", "Invalid UTC cohort date.");
  const result = new Date(value);
  if (!Number.isFinite(result.getTime()) || result.toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid calendar date.");
  return result;
}
export function parseCohortQuery(value: unknown, now = new Date()): CohortQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "from", "to", "limit", "offset",
    "includeEmpty", "order", "overdueHours",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown capture cohort filter.");
  if (raw.includeEmpty !== undefined && typeof raw.includeEmpty !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeEmpty flag.");
  const to = raw.to === undefined ? now : date(raw.to);
  const from = raw.from === undefined ?
    new Date(to.getTime() - 90 * 86400000) : date(raw.from);
  if (from >= to || to.getTime() - from.getTime() > 366 * 86400000)
    throw new WorkInputError("INVALID", "Capture cohort range must be 1–366 days.");
  if (raw.order !== undefined && ![
    "RECENT", "OLDEST", "MOST_OPEN", "MOST_OVERDUE",
  ].includes(String(raw.order)))
    throw new WorkInputError("INVALID", "Invalid cohort order.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    from, to,
    limit: number(raw.limit ?? 25, 1, 100),
    offset: number(raw.offset ?? 0, 0, 1000000),
    overdueHours: number(raw.overdueHours ?? 48, 1, 8760),
    includeEmpty: raw.includeEmpty !== false,
    order: (raw.order ?? "RECENT") as CohortQuery["order"],
  };
}
export function cohortDigest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function median(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle]! :
    (sorted[middle - 1]! + sorted[middle]!) / 2;
}
function percent(a: number, b: number) {
  return b ? Math.round((a / b) * 10000) / 100 : 0;
}
export function buildCohortRow(
  capture: CohortCapture, tasks: CohortTask[],
  escalations: CohortEscalation[], notices: CohortNotification[],
  checks: CohortProvider[], query: CohortQuery, now: Date,
): CohortRow {
  const ids = new Set(tasks.map(task => task.id));
  const scopedEscalations = escalations.filter(x => ids.has(x.taskId));
  const scopedNotices = notices.filter(x => ids.has(x.taskId));
  const scopedChecks = checks.filter(x => ids.has(x.taskId));
  const activeTasks = tasks.filter(x =>
    x.disposition !== "RESOLVED" && x.disposition !== "WAIVED");
  const closedTasks = tasks.filter(x =>
    x.disposition === "RESOLVED" || x.disposition === "WAIVED");
  const overdue = activeTasks.filter(x =>
    now.getTime() - x.createdAt.getTime() > query.overdueHours * 3600000).length;
  const durations = activeTasks.map(x =>
    Math.max(0, (now.getTime() - x.createdAt.getTime()) / 3600000));
  const checked = new Map<string, CohortProvider>();
  for (const check of scopedChecks) {
    const old = checked.get(check.taskId);
    if (!old || old.checkedAt < check.checkedAt ||
        (old.checkedAt.getTime() === check.checkedAt.getTime() &&
          old.id.localeCompare(check.id) < 0))
      checked.set(check.taskId, check);
  }
  const outcomes = [...checked.values()];
  const passing = outcomes.filter(x => x.outcome === "PASS").length;
  const failing = outcomes.filter(x => x.outcome === "FAIL" || x.outcome === "ERROR").length;
  const unknown = tasks.length - passing - failing;
  const severity: Record<string, number> = {};
  for (const task of tasks)
    severity[task.severity] = (severity[task.severity] ?? 0) + 1;
  const anomalies: string[] = [];
  if (tasks.some(x => x.createdAt < capture.createdAt))
    anomalies.push("TASK_BEFORE_CAPTURE");
  if (tasks.some(x => x.completedAt && x.completedAt < x.createdAt))
    anomalies.push("TASK_COMPLETED_BEFORE_CREATION");
  if (scopedNotices.some(x => x.readAt && x.readAt < x.createdAt))
    anomalies.push("NOTIFICATION_READ_BEFORE_CREATION");
  if (scopedEscalations.some(x =>
    x.acknowledgedAt && x.acknowledgedAt < x.openedAt))
    anomalies.push("ESCALATION_ACK_BEFORE_OPEN");
  if (closedTasks.some(x => x.completedAt === null))
    anomalies.push("CLOSED_TASK_WITHOUT_COMPLETION");
  const longestOpenHours = durations.length ? Math.max(...durations) : 0;
  const canonical = {
    captureId: capture.id, createdAt: capture.createdAt.toISOString(),
    totalTasks: tasks.length, open: activeTasks.length,
    inReview: tasks.filter(x => x.disposition === "IN_REVIEW").length,
    resolved: tasks.filter(x => x.disposition === "RESOLVED").length,
    waived: tasks.filter(x => x.disposition === "WAIVED").length,
    overdue, unassigned: activeTasks.filter(x => !x.ownerUserId).length,
    requiredOpen: activeTasks.filter(x => x.required).length,
    severity,
    activeEscalations: scopedEscalations.filter(x =>
      x.state === "OPEN" || x.state === "ACKNOWLEDGED").length,
    acknowledgedEscalations: scopedEscalations.filter(x =>
      x.state === "ACKNOWLEDGED").length,
    closedEscalations: scopedEscalations.filter(x =>
      x.state === "RESOLVED" || x.state === "CANCELLED").length,
    highestEscalationLevel: scopedEscalations.length ?
      Math.max(...scopedEscalations.map(x => x.level)) : 0,
    notifications: scopedNotices.length,
    unread: scopedNotices.filter(x => !x.readAt && !x.dismissedAt).length,
    dismissed: scopedNotices.filter(x => x.dismissedAt).length,
    providerCheckedTasks: outcomes.length,
    providerFailingTasks: failing,
    providerPassedTasks: passing,
    providerUnknownTasks: unknown,
    providerLastCheckedAt: scopedChecks.length ?
      new Date(Math.max(...scopedChecks.map(x => x.checkedAt.getTime()))).toISOString() : null,
    oldestOpenAt: activeTasks.length ?
      new Date(Math.min(...activeTasks.map(x => x.createdAt.getTime()))).toISOString() : null,
    longestOpenHours: Math.round(longestOpenHours * 100) / 100,
    medianOpenHours: Math.round(median(durations) * 100) / 100,
    coverage: {
      activeOwnerPercent: percent(activeTasks.filter(x => x.ownerUserId).length, activeTasks.length),
      providerCheckedPercent: percent(outcomes.length, tasks.length),
      closedPercent: percent(closedTasks.length, tasks.length),
    },
    anomalies: anomalies.sort(),
  };
  return { ...canonical, digest: cohortDigest(canonical) };
}
export function cohortSort(rows: CohortRow[], order: CohortQuery["order"]) {
  return [...rows].sort((a, b) => {
    if (order === "MOST_OPEN")
      return b.open - a.open || a.captureId.localeCompare(b.captureId);
    if (order === "MOST_OVERDUE")
      return b.overdue - a.overdue || a.captureId.localeCompare(b.captureId);
    if (order === "OLDEST")
      return a.createdAt.localeCompare(b.createdAt) ||
        a.captureId.localeCompare(b.captureId);
    return b.createdAt.localeCompare(a.createdAt) ||
      a.captureId.localeCompare(b.captureId);
  });
}
export function cohortTotals(rows: CohortRow[]): CohortTotals {
  const totals: CohortTotals = {
    captures: rows.length, tasks: 0, open: 0, resolved: 0, waived: 0,
    overdue: 0, unassigned: 0, activeEscalations: 0, unread: 0,
    providerFailingTasks: 0, providerUnknownTasks: 0,
  };
  for (const row of rows) {
    totals.tasks += row.totalTasks;
    totals.open += row.open;
    totals.resolved += row.resolved;
    totals.waived += row.waived;
    totals.overdue += row.overdue;
    totals.unassigned += row.unassigned;
    totals.activeEscalations += row.activeEscalations;
    totals.unread += row.unread;
    totals.providerFailingTasks += row.providerFailingTasks;
    totals.providerUnknownTasks += row.providerUnknownTasks;
  }
  return totals;
}
export function buildCohortReport(
  organizationId: string, query: CohortQuery, captures: CohortCapture[],
  tasks: CohortTask[], escalations: CohortEscalation[],
  notices: CohortNotification[], checks: CohortProvider[],
  totalCaptures: number, now: Date,
): CohortReport {
  const rows = cohortSort(captures.map(capture => buildCohortRow(
    capture, tasks.filter(x => x.captureId === capture.id),
    escalations, notices, checks, query, now,
  )).filter(row => query.includeEmpty || row.totalTasks > 0), query.order);
  const canonical = {
    schema: "cyberpilot.integrity.capture.cohorts.v1" as const,
    organizationId, generatedAt: now.toISOString(),
    from: query.from.toISOString(), to: query.to.toISOString(),
    offset: query.offset, limit: query.limit, totalCaptures,
    hasMore: query.offset + captures.length < totalCaptures,
    complete: query.offset === 0 && captures.length === totalCaptures,
    order: query.order, rows, totalsOnPage: cohortTotals(rows),
  };
  return {
    ...canonical, digest: cohortDigest(canonical),
    limitations: [
      "Cohort summaries and nonchronological ordering cover only the fetched capture page.",
      "A provider PASS is an observation at a historical instant, not proof of current safety.",
      "Open age is derived from creation time; the policy is diagnostic, not contractual SLA.",
      "No changes are made to task, escalations, evidence, remediation or CyberScore.",
      "Cross-capture totals are incomplete whenever the page does not cover all captures.",
    ],
  };
}
export async function readIntegrityCaptureCohorts(
  scope: ReviewScope, value: unknown, now = new Date(),
): Promise<CohortReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Capture cohort reporting requires an administrator.");
  const query = parseCohortQuery(value, now);
  const where = {
    organizationId: scope.organizationId,
    createdAt: { gte: query.from, lt: query.to },
    ...(query.captureId ? { id: query.captureId } : {}),
  };
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: { id: query.captureId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!capture) throw new WorkInputError("MISSING", "Capture not found.");
  }
  const [total, captures] = await db.$transaction([
    db.integrityCaseCapture.count({ where }),
    db.integrityCaseCapture.findMany({
      where, orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
      select: { id: true, createdAt: true },
    }),
  ]);
  const captureIds = captures.map(x => x.id);
  if (!captureIds.length)
    return buildCohortReport(scope.organizationId, query, [], [], [], [], [], total, now);
  const tasks = await db.integrityReviewTask.findMany({
    where: { organizationId: scope.organizationId, captureId: { in: captureIds } },
    take: 10000,
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    select: {
      id: true, captureId: true, severity: true, disposition: true,
      createdAt: true, completedAt: true, ownerUserId: true, required: true,
    },
  });
  const ids = tasks.map(x => x.id);
  if (!ids.length)
    return buildCohortReport(scope.organizationId, query, captures, tasks, [], [], [], total, now);
  const whereTask = { organizationId: scope.organizationId, taskId: { in: ids } };
  const [escalations, notices, checks] = await Promise.all([
    db.integrityEscalation.findMany({
      where: whereTask, take: 15000,
      orderBy: [{ openedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, state: true, level: true, openedAt: true,
        acknowledgedAt: true, resolvedAt: true,
      },
    }),
    db.integrityNotification.findMany({
      where: whereTask, take: 15000,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, kind: true,
        createdAt: true, readAt: true, dismissedAt: true,
      },
    }),
    db.integrityProviderCheck.findMany({
      where: whereTask, take: 15000,
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, outcome: true, checkedAt: true,
      },
    }),
  ]);
  const report = buildCohortReport(
    scope.organizationId, query, captures, tasks, escalations, notices,
    checks, total, now);
  if (tasks.length === 10000 ||
      [escalations, notices, checks].some(x => x.length === 15000)) {
    report.complete = false;
    report.limitations.push("At least one record collection hit its query cap; counts are partial.");
  }
  return report;
}
