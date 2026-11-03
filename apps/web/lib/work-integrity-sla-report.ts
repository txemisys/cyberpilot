import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Administrative SLA investigation for persisted operational events.
 * Targets are reporting thresholds, not promises of external delivery.
 */
export type SlaQuery = {
  captureId?: string;
  from: Date;
  to: Date;
  responseMinutes: number;
  resolutionMinutes: number;
  notificationReadMinutes: number;
  escalationAckMinutes: number;
  limit: number;
  includeClosed: boolean;
};
export type SlaTask = {
  id: string;
  captureId: string;
  severity: string;
  disposition: string;
  createdAt: Date;
  completedAt: Date | null;
  ownerUserId: string | null;
  revision: number;
};
export type SlaNotification = {
  id: string;
  taskId: string;
  createdAt: Date;
  readAt: Date | null;
  dismissedAt: Date | null;
  kind: string;
};
export type SlaEscalation = {
  id: string;
  taskId: string;
  state: string;
  openedAt: Date;
  acknowledgedAt: Date | null;
  resolvedAt: Date | null;
  dueAt: Date;
  level: number;
};
export type SlaEvent = {
  id: string;
  taskId: string;
  action: string;
  occurredAt: Date;
  revisionAfter: number;
};
export type SlaBreach = {
  entity: "TASK" | "NOTIFICATION" | "ESCALATION";
  id: string;
  taskId: string;
  category: "FIRST_RESPONSE" | "RESOLUTION" |
    "READ" | "ACKNOWLEDGEMENT" | "DUE";
  elapsedMinutes: number;
  thresholdMinutes: number;
  exceededMinutes: number;
  active: boolean;
  startedAt: string;
  endedAt: string | null;
  state: string;
  sourceDigest: string;
};
export type SlaReport = {
  schema: "cyberpilot.integrity.sla.v1";
  generatedAt: string;
  from: string;
  to: string;
  captureId: string | null;
  scannedTasks: number;
  totalTasks: number;
  scannedNotifications: number;
  scannedEscalations: number;
  scannedEvents: number;
  truncated: boolean;
  counts: Record<SlaBreach["category"], number>;
  active: number;
  historical: number;
  affectedTasks: number;
  breaches: SlaBreach[];
  digest: string;
  warnings: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected SLA query object.");
  return value as Record<string, unknown>;
}
function int(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
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
export function parseSlaQuery(value: unknown, now = new Date()): SlaQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "from", "to", "responseMinutes",
    "resolutionMinutes", "notificationReadMinutes",
    "escalationAckMinutes", "limit", "includeClosed",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown SLA query field.");
  const to = raw.to === undefined ? now : date(raw.to, "to");
  const from = raw.from === undefined ?
    new Date(to.getTime() - 30 * 86400000) : date(raw.from, "from");
  if (from.getTime() >= to.getTime() ||
      to.getTime() - from.getTime() > 366 * 86400000)
    throw new WorkInputError("INVALID", "SLA range must be 1–366 days.");
  if (raw.includeClosed !== undefined && typeof raw.includeClosed !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeClosed flag.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    from, to,
    responseMinutes: int(raw.responseMinutes ?? 1440, "responseMinutes", 1, 525600),
    resolutionMinutes: int(raw.resolutionMinutes ?? 10080, "resolutionMinutes", 1, 525600),
    notificationReadMinutes: int(raw.notificationReadMinutes ?? 1440,
      "notificationReadMinutes", 1, 525600),
    escalationAckMinutes: int(raw.escalationAckMinutes ?? 240,
      "escalationAckMinutes", 1, 525600),
    limit: int(raw.limit ?? 500, "limit", 1, 2000),
    includeClosed: raw.includeClosed !== false,
  };
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function minutes(from: Date, to: Date) {
  return Math.max(0, (to.getTime() - from.getTime()) / 60000);
}
function firstResponse(events: SlaEvent[], taskId: string) {
  const matching = events.filter(event =>
    event.taskId === taskId &&
    ["ACKNOWLEDGE", "START_REVIEW", "RESOLVE", "WAIVE"].includes(event.action));
  matching.sort((a, b) =>
    a.occurredAt.getTime() - b.occurredAt.getTime() ||
    a.id.localeCompare(b.id));
  return matching[0]?.occurredAt ?? null;
}
export function computeSlaReport(
  query: SlaQuery,
  input: {
    tasks: SlaTask[];
    notifications: SlaNotification[];
    escalations: SlaEscalation[];
    events: SlaEvent[];
    totalTasks: number;
    truncated: boolean;
  },
  now = new Date(),
): SlaReport {
  const breaches: SlaBreach[] = [];
  const taskSet = new Set(input.tasks.map(task => task.id));
  const add = (
    entity: SlaBreach["entity"], id: string, taskId: string,
    category: SlaBreach["category"], start: Date,
    end: Date | null, threshold: number, state: string,
  ) => {
    const elapsedMinutes = minutes(start, end ?? now);
    if (elapsedMinutes <= threshold) return;
    const row = {
      entity, id, taskId, category,
      elapsedMinutes: Math.round(elapsedMinutes * 100) / 100,
      thresholdMinutes: threshold,
      exceededMinutes: Math.round((elapsedMinutes - threshold) * 100) / 100,
      active: end === null, startedAt: start.toISOString(),
      endedAt: end?.toISOString() ?? null, state,
    };
    breaches.push({ ...row, sourceDigest: digest(row) });
  };
  for (const task of input.tasks) {
    const response = firstResponse(input.events, task.id);
    add("TASK", task.id, task.id, "FIRST_RESPONSE",
      task.createdAt, response, query.responseMinutes, task.disposition);
    const finished = task.completedAt;
    add("TASK", task.id, task.id, "RESOLUTION",
      task.createdAt, finished, query.resolutionMinutes, task.disposition);
  }
  for (const notification of input.notifications) {
    if (!taskSet.has(notification.taskId)) continue;
    const end = notification.readAt ?? notification.dismissedAt;
    add("NOTIFICATION", notification.id, notification.taskId,
      "READ", notification.createdAt, end,
      query.notificationReadMinutes, notification.kind);
  }
  for (const escalation of input.escalations) {
    if (!taskSet.has(escalation.taskId)) continue;
    const end = escalation.acknowledgedAt ?? escalation.resolvedAt;
    add("ESCALATION", escalation.id, escalation.taskId,
      "ACKNOWLEDGEMENT", escalation.openedAt, end,
      query.escalationAckMinutes, escalation.state);
    if (escalation.dueAt < (escalation.resolvedAt ?? now)) {
      add("ESCALATION", escalation.id, escalation.taskId,
        "DUE", escalation.dueAt, escalation.resolvedAt,
        0, escalation.state);
    }
  }
  breaches.sort((a, b) =>
    Number(b.active) - Number(a.active) ||
    b.exceededMinutes - a.exceededMinutes ||
    a.category.localeCompare(b.category) ||
    a.id.localeCompare(b.id));
  const counts: SlaReport["counts"] = {
    FIRST_RESPONSE: 0, RESOLUTION: 0, READ: 0,
    ACKNOWLEDGEMENT: 0, DUE: 0,
  };
  for (const row of breaches) counts[row.category]++;
  const canonical = {
    schema: "cyberpilot.integrity.sla.v1" as const,
    from: query.from.toISOString(), to: query.to.toISOString(),
    captureId: query.captureId ?? null,
    scannedTasks: input.tasks.length,
    totalTasks: input.totalTasks,
    scannedNotifications: input.notifications.length,
    scannedEscalations: input.escalations.length,
    scannedEvents: input.events.length,
    truncated: input.truncated,
    counts,
    active: breaches.filter(row => row.active).length,
    historical: breaches.filter(row => !row.active).length,
    affectedTasks: new Set(breaches.map(row => row.taskId)).size,
    breaches,
  };
  return {
    ...canonical, generatedAt: now.toISOString(),
    digest: digest(canonical),
    warnings: [
      "Thresholds are reporting configuration, not contractual SLA guarantees.",
      "A missing response event is treated as no recorded first response.",
      "Read state is not proof of human attention or external delivery.",
      "Resolution is measured from persisted task creation to completion.",
      "Truncated reports must not be interpreted as organization-wide results.",
      "Operational SLA findings do not modify CyberScore or security gates.",
    ],
  };
}
export async function readIntegritySlaReport(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "SLA reporting requires an administrator.");
  const query = parseSlaQuery(value, now);
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: { organizationId: scope.organizationId, id: query.captureId },
      select: { id: true },
    });
    if (!capture)
      throw new WorkInputError("MISSING", "Capture not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    createdAt: { gte: query.from, lt: query.to },
    ...(query.captureId ? { captureId: query.captureId } : {}),
    ...(query.includeClosed ? {} : {
      completedAt: null,
    }),
  };
  const [totalTasks, tasks] = await Promise.all([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, take: query.limit,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      select: {
        id: true, captureId: true, severity: true,
        disposition: true, createdAt: true, completedAt: true,
        ownerUserId: true, revision: true,
      },
    }),
  ]);
  const taskIds = tasks.map(task => task.id);
  const relatedWhere = {
    organizationId: scope.organizationId,
    taskId: { in: taskIds },
  };
  const cap = 10000;
  const [notifications, escalations, events] = taskIds.length ?
    await Promise.all([
      db.integrityNotification.findMany({
        where: relatedWhere,
        take: cap, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, createdAt: true,
          readAt: true, dismissedAt: true, kind: true,
        },
      }),
      db.integrityEscalation.findMany({
        where: relatedWhere,
        take: cap, orderBy: [{ openedAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, state: true, openedAt: true,
          acknowledgedAt: true, resolvedAt: true, dueAt: true,
          level: true,
        },
      }),
      db.integrityReviewEvent.findMany({
        where: relatedWhere,
        take: cap, orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, action: true,
          occurredAt: true, revisionAfter: true,
        },
      }),
    ]) : [[], [], []];
  return computeSlaReport(query, {
    tasks, notifications, escalations, events, totalTasks,
    truncated: totalTasks > tasks.length ||
      notifications.length >= cap ||
      escalations.length >= cap || events.length >= cap,
  }, now);
}
