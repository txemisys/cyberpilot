import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Operational metrics are observational and cannot be used as security
 * assurance, independent verification, or automatic remediation closure.
 */
export type OperationsMetricsQuery = {
  captureId?: string;
  from: Date;
  to: Date;
  interval: "DAY" | "WEEK";
  limit: number;
};
export type OperationsMetricPoint = {
  period: string;
  created: number;
  resolved: number;
  waived: number;
  escalationsOpened: number;
  escalationsAcknowledged: number;
  escalationsClosed: number;
  notificationsCreated: number;
  notificationsRead: number;
  notificationsDismissed: number;
  providerChecks: number;
  providerPassed: number;
  providerFailed: number;
};
export type OperationsMetricSummary = {
  tasksCreated: number;
  reviewsResolved: number;
  reviewsWaived: number;
  escalationsOpened: number;
  escalationsActive: number;
  notificationsCreated: number;
  notificationsRead: number;
  providerChecks: number;
  providerPassed: number;
  providerFailed: number;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected metrics query object.");
  return value as Record<string, unknown>;
}
function date(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) ||
      parsed.toISOString() !==
        (value.includes(".") ? value : value.replace("Z", ".000Z")))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return parsed;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseOperationsMetricsQuery(
  value: unknown, now = new Date(),
): OperationsMetricsQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "from", "to", "interval", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown metrics query field.");
  const to = raw.to === undefined ? now : date(raw.to, "to");
  const from = raw.from === undefined ?
    new Date(to.getTime() - 30 * 86400000) : date(raw.from, "from");
  if (from.getTime() >= to.getTime() ||
      to.getTime() - from.getTime() > 366 * 86400000)
    throw new WorkInputError("INVALID", "Metrics range must be 1–366 days.");
  if (raw.interval !== undefined && !["DAY", "WEEK"].includes(String(raw.interval)))
    throw new WorkInputError("INVALID", "Invalid metrics interval.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    from, to,
    interval: (raw.interval ?? "DAY") as "DAY" | "WEEK",
    limit: integer(raw.limit ?? 100, "limit", 1, 400),
  };
}
export function metricsPeriod(dateValue: Date, interval: "DAY" | "WEEK") {
  const date = new Date(Date.UTC(
    dateValue.getUTCFullYear(),
    dateValue.getUTCMonth(),
    dateValue.getUTCDate(),
  ));
  if (interval === "WEEK") {
    const daysFromMonday = (date.getUTCDay() + 6) % 7;
    date.setUTCDate(date.getUTCDate() - daysFromMonday);
  }
  return date.toISOString().slice(0, 10);
}
function point(period: string): OperationsMetricPoint {
  return {
    period, created: 0, resolved: 0, waived: 0,
    escalationsOpened: 0, escalationsAcknowledged: 0,
    escalationsClosed: 0, notificationsCreated: 0,
    notificationsRead: 0, notificationsDismissed: 0,
    providerChecks: 0, providerPassed: 0, providerFailed: 0,
  };
}
export function rollupMetrics(
  query: OperationsMetricsQuery,
  input: {
    tasks: Array<{ createdAt: Date; disposition: string; completedAt: Date | null }>;
    escalations: Array<{
      openedAt: Date; acknowledgedAt: Date | null;
      resolvedAt: Date | null; state: string;
    }>;
    notifications: Array<{
      createdAt: Date; readAt: Date | null; dismissedAt: Date | null;
    }>;
    checks: Array<{ checkedAt: Date; outcome: string }>;
  },
) {
  const buckets = new Map<string, OperationsMetricPoint>();
  const within = (time: Date) =>
    time.getTime() >= query.from.getTime() &&
    time.getTime() < query.to.getTime();
  const record = (time: Date, key: keyof Omit<OperationsMetricPoint, "period">) => {
    if (!within(time)) return;
    const period = metricsPeriod(time, query.interval);
    const current = buckets.get(period) ?? point(period);
    current[key]++;
    buckets.set(period, current);
  };
  for (const task of input.tasks) {
    record(task.createdAt, "created");
    if (task.completedAt && task.disposition === "RESOLVED")
      record(task.completedAt, "resolved");
    if (task.completedAt && task.disposition === "WAIVED")
      record(task.completedAt, "waived");
  }
  for (const escalation of input.escalations) {
    record(escalation.openedAt, "escalationsOpened");
    if (escalation.acknowledgedAt)
      record(escalation.acknowledgedAt, "escalationsAcknowledged");
    if (escalation.resolvedAt)
      record(escalation.resolvedAt, "escalationsClosed");
  }
  for (const notification of input.notifications) {
    record(notification.createdAt, "notificationsCreated");
    if (notification.readAt)
      record(notification.readAt, "notificationsRead");
    if (notification.dismissedAt)
      record(notification.dismissedAt, "notificationsDismissed");
  }
  for (const check of input.checks) {
    record(check.checkedAt, "providerChecks");
    if (check.outcome === "PASS")
      record(check.checkedAt, "providerPassed");
    if (check.outcome === "FAIL")
      record(check.checkedAt, "providerFailed");
  }
  const periods = [...buckets.values()]
    .sort((a, b) => a.period.localeCompare(b.period));
  const summary: OperationsMetricSummary = {
    tasksCreated: 0, reviewsResolved: 0, reviewsWaived: 0,
    escalationsOpened: 0, escalationsActive: 0,
    notificationsCreated: 0, notificationsRead: 0,
    providerChecks: 0, providerPassed: 0, providerFailed: 0,
  };
  for (const row of periods) {
    summary.tasksCreated += row.created;
    summary.reviewsResolved += row.resolved;
    summary.reviewsWaived += row.waived;
    summary.escalationsOpened += row.escalationsOpened;
    summary.notificationsCreated += row.notificationsCreated;
    summary.notificationsRead += row.notificationsRead;
    summary.providerChecks += row.providerChecks;
    summary.providerPassed += row.providerPassed;
    summary.providerFailed += row.providerFailed;
  }
  summary.escalationsActive = input.escalations.filter(
    row => ["OPEN", "ACKNOWLEDGED"].includes(row.state),
  ).length;
  return { periods, summary };
}
export async function readIntegrityOperationsMetrics(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Operations metrics denied.");
  const query = parseOperationsMetricsQuery(value, now);
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: { id: query.captureId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!capture)
      throw new WorkInputError("MISSING", "Capture not found.");
  }
  const taskWhere = {
    organizationId: scope.organizationId,
    ...(query.captureId ? { captureId: query.captureId } : {}),
  };
  const taskIds = query.captureId ?
    (await db.integrityReviewTask.findMany({
      where: taskWhere, select: { id: true },
    })).map(task => task.id) : null;
  const scoped = taskIds ? { taskId: { in: taskIds } } : {};
  const timeWindow = { gte: query.from, lt: query.to };
  const [tasks, escalations, notifications, checks] = await Promise.all([
    db.integrityReviewTask.findMany({
      where: {
        ...taskWhere,
        OR: [
          { createdAt: timeWindow },
          { completedAt: timeWindow },
        ],
      },
      select: {
        createdAt: true, disposition: true, completedAt: true,
      },
      take: 20000,
    }),
    db.integrityEscalation.findMany({
      where: {
        organizationId: scope.organizationId, ...scoped,
        OR: [
          { openedAt: timeWindow }, { acknowledgedAt: timeWindow },
          { resolvedAt: timeWindow },
        ],
      },
      select: {
        openedAt: true, acknowledgedAt: true,
        resolvedAt: true, state: true,
      },
      take: 20000,
    }),
    db.integrityNotification.findMany({
      where: {
        organizationId: scope.organizationId, ...scoped,
        OR: [
          { createdAt: timeWindow }, { readAt: timeWindow },
          { dismissedAt: timeWindow },
        ],
      },
      select: {
        createdAt: true, readAt: true, dismissedAt: true,
      },
      take: 20000,
    }),
    db.integrityProviderCheck.findMany({
      where: {
        organizationId: scope.organizationId, ...scoped,
        checkedAt: timeWindow,
      },
      select: { checkedAt: true, outcome: true },
      take: 20000,
    }),
  ]);
  const result = rollupMetrics(query, {
    tasks, escalations, notifications, checks,
  });
  const periods = result.periods.slice(0, query.limit);
  const canonical = {
    organizationId: scope.organizationId,
    captureId: query.captureId ?? null,
    from: query.from.toISOString(), to: query.to.toISOString(),
    interval: query.interval, periods,
  };
  return {
    ...canonical, summary: result.summary,
    totalPeriods: result.periods.length,
    truncatedPeriods: result.periods.length > query.limit,
    dataLimitReached: [
      tasks, escalations, notifications, checks,
    ].some(rows => rows.length >= 20000),
    digest: createHash("sha256")
      .update(JSON.stringify(canonical)).digest("hex"),
    limitations: [
      "This report measures operations, not effective security posture.",
      "Completed review does not establish independent verification.",
      "Provider checks count observations, not unique remediated controls.",
      "At most 20,000 records per category are queried; a cap is flagged.",
      "Historical task dispositions are not reconstructed from event history.",
      "Summary covers the full queried interval, while periods may be truncated.",
    ],
  };
}
