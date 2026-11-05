import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Cross-record operational consistency audit. This detects missing and
 * contradictory workflow links; it does not verify security evidence.
 */
export type ConsistencyQuery = {
  captureId?: string;
  offset: number;
  limit: number;
  includeResolved: boolean;
};
export type ConsistencyTask = {
  id: string;
  captureId: string;
  disposition: string;
  revision: number;
  ownerUserId: string | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};
export type ConsistencyNotification = {
  id: string;
  taskId: string;
  recipientUserId: string;
  kind: string;
  revision: number;
  createdAt: Date;
  readAt: Date | null;
  dismissedAt: Date | null;
};
export type ConsistencyEscalation = {
  id: string;
  taskId: string;
  state: string;
  level: number;
  revision: number;
  openedAt: Date;
  dueAt: Date;
  acknowledgedAt: Date | null;
  resolvedAt: Date | null;
};
export type ConsistencyEvent = {
  id: string;
  taskId: string;
  revisionBefore: number;
  revisionAfter: number;
  before: string;
  after: string;
  action: string;
  occurredAt: Date;
};
export type ConsistencyIssueCode =
  | "TASK_REVISION_INVALID"
  | "TASK_CLOSED_WITHOUT_COMPLETION"
  | "TASK_OPEN_WITH_COMPLETION"
  | "TASK_COMPLETED_BEFORE_CREATION"
  | "TASK_OWNER_MISSING"
  | "EVENT_REVISION_GAP"
  | "EVENT_REVISION_CONFLICT"
  | "EVENT_DISPOSITION_CONFLICT"
  | "EVENT_FUTURE_REVISION"
  | "EVENT_CREATED_BEFORE_TASK"
  | "NOTIFICATION_REVISION_INVALID"
  | "NOTIFICATION_BEFORE_TASK"
  | "NOTIFICATION_READ_BEFORE_CREATION"
  | "NOTIFICATION_DISMISSED_BEFORE_CREATION"
  | "ESCALATION_REVISION_INVALID"
  | "ESCALATION_BEFORE_TASK"
  | "ESCALATION_ACK_BEFORE_OPEN"
  | "ESCALATION_RESOLVED_BEFORE_OPEN"
  | "ESCALATION_CLOSED_WITHOUT_RESOLUTION"
  | "ESCALATION_ACTIVE_WITH_RESOLUTION"
  | "ESCALATION_DUE_BEFORE_OPEN";
export type ConsistencyIssue = {
  code: ConsistencyIssueCode;
  taskId: string;
  entity: "TASK" | "EVENT" | "NOTIFICATION" | "ESCALATION";
  entityId: string;
  severity: "ERROR" | "WARNING";
  details: Record<string, string | number | boolean | null>;
};
export type ConsistencyTaskReport = {
  taskId: string;
  captureId: string;
  disposition: string;
  revision: number;
  events: number;
  notifications: number;
  escalations: number;
  consistent: boolean;
  issues: ConsistencyIssue[];
  digest: string;
};
export type ConsistencyReport = {
  schema: "cyberpilot.integrity.workflow.consistency.v1";
  organizationId: string;
  captureId: string | null;
  offset: number;
  limit: number;
  totalTasks: number;
  hasMore: boolean;
  complete: boolean;
  generatedAt: string;
  scanned: number;
  consistent: number;
  inconsistent: number;
  issueCounts: Partial<Record<ConsistencyIssueCode, number>>;
  tasks: ConsistencyTaskReport[];
  digest: string;
  limitations: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected consistency query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseConsistencyQuery(value: unknown): ConsistencyQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit", "includeResolved",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown consistency field.");
  if (raw.includeResolved !== undefined &&
      typeof raw.includeResolved !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeResolved flag.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    includeResolved: raw.includeResolved !== false,
  };
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function inspectConsistencyTask(
  task: ConsistencyTask,
  events: ConsistencyEvent[],
  notifications: ConsistencyNotification[],
  escalations: ConsistencyEscalation[],
): ConsistencyTaskReport {
  const issues: ConsistencyIssue[] = [];
  const issue = (
    code: ConsistencyIssueCode,
    entity: ConsistencyIssue["entity"],
    entityId: string,
    severity: ConsistencyIssue["severity"],
    details: ConsistencyIssue["details"] = {},
  ) => issues.push({
    code, taskId: task.id, entity, entityId, severity, details,
  });
  if (!Number.isSafeInteger(task.revision) || task.revision < 1)
    issue("TASK_REVISION_INVALID", "TASK", task.id, "ERROR",
      { revision: task.revision });
  const closed = ["RESOLVED", "WAIVED"].includes(task.disposition);
  if (closed && !task.completedAt)
    issue("TASK_CLOSED_WITHOUT_COMPLETION", "TASK", task.id, "ERROR");
  if (!closed && task.completedAt)
    issue("TASK_OPEN_WITH_COMPLETION", "TASK", task.id, "ERROR");
  if (task.completedAt && task.completedAt < task.createdAt)
    issue("TASK_COMPLETED_BEFORE_CREATION", "TASK", task.id, "ERROR");
  if (!task.ownerUserId && !closed)
    issue("TASK_OWNER_MISSING", "TASK", task.id, "WARNING");
  const ordered = [...events].sort((a, b) =>
    a.revisionAfter - b.revisionAfter ||
    a.occurredAt.getTime() - b.occurredAt.getTime() ||
    a.id.localeCompare(b.id));
  let previousRevision = 1;
  let previousDisposition: string | null = null;
  for (const event of ordered) {
    if (event.revisionBefore !== previousRevision ||
        event.revisionAfter !== previousRevision + 1)
      issue("EVENT_REVISION_GAP", "EVENT", event.id, "ERROR", {
        expectedBefore: previousRevision,
        actualBefore: event.revisionBefore,
        actualAfter: event.revisionAfter,
      });
    if (previousDisposition && previousDisposition !== event.before)
      issue("EVENT_DISPOSITION_CONFLICT", "EVENT", event.id, "ERROR", {
        expectedBefore: previousDisposition,
        actualBefore: event.before,
      });
    if (event.revisionAfter > task.revision)
      issue("EVENT_FUTURE_REVISION", "EVENT", event.id, "ERROR", {
        taskRevision: task.revision, eventRevision: event.revisionAfter,
      });
    if (event.occurredAt < task.createdAt)
      issue("EVENT_CREATED_BEFORE_TASK", "EVENT", event.id, "WARNING");
    if (event.revisionAfter <= previousRevision)
      issue("EVENT_REVISION_CONFLICT", "EVENT", event.id, "ERROR");
    previousRevision = Math.max(previousRevision, event.revisionAfter);
    previousDisposition = event.after;
  }
  if (previousDisposition && previousDisposition !== task.disposition)
    issue("EVENT_DISPOSITION_CONFLICT", "TASK", task.id, "ERROR", {
      expectedAfter: previousDisposition,
      actualAfter: task.disposition,
    });
  for (const notification of notifications) {
    if (!Number.isSafeInteger(notification.revision) ||
        notification.revision < 1)
      issue("NOTIFICATION_REVISION_INVALID", "NOTIFICATION",
        notification.id, "ERROR", { revision: notification.revision });
    if (notification.createdAt < task.createdAt)
      issue("NOTIFICATION_BEFORE_TASK", "NOTIFICATION",
        notification.id, "WARNING");
    if (notification.readAt && notification.readAt < notification.createdAt)
      issue("NOTIFICATION_READ_BEFORE_CREATION", "NOTIFICATION",
        notification.id, "ERROR");
    if (notification.dismissedAt &&
        notification.dismissedAt < notification.createdAt)
      issue("NOTIFICATION_DISMISSED_BEFORE_CREATION", "NOTIFICATION",
        notification.id, "ERROR");
  }
  for (const escalation of escalations) {
    if (!Number.isSafeInteger(escalation.revision) ||
        escalation.revision < 1)
      issue("ESCALATION_REVISION_INVALID", "ESCALATION",
        escalation.id, "ERROR", { revision: escalation.revision });
    if (escalation.openedAt < task.createdAt)
      issue("ESCALATION_BEFORE_TASK", "ESCALATION",
        escalation.id, "WARNING");
    if (escalation.dueAt < escalation.openedAt)
      issue("ESCALATION_DUE_BEFORE_OPEN", "ESCALATION",
        escalation.id, "WARNING");
    if (escalation.acknowledgedAt &&
        escalation.acknowledgedAt < escalation.openedAt)
      issue("ESCALATION_ACK_BEFORE_OPEN", "ESCALATION",
        escalation.id, "ERROR");
    if (escalation.resolvedAt &&
        escalation.resolvedAt < escalation.openedAt)
      issue("ESCALATION_RESOLVED_BEFORE_OPEN", "ESCALATION",
        escalation.id, "ERROR");
    const inactive = ["RESOLVED", "CANCELLED"].includes(escalation.state);
    if (inactive && !escalation.resolvedAt)
      issue("ESCALATION_CLOSED_WITHOUT_RESOLUTION", "ESCALATION",
        escalation.id, "ERROR");
    if (!inactive && escalation.resolvedAt)
      issue("ESCALATION_ACTIVE_WITH_RESOLUTION", "ESCALATION",
        escalation.id, "ERROR");
  }
  issues.sort((a, b) =>
    a.entity.localeCompare(b.entity) ||
    a.entityId.localeCompare(b.entityId) ||
    a.code.localeCompare(b.code));
  const canonical = {
    taskId: task.id, captureId: task.captureId,
    disposition: task.disposition, revision: task.revision,
    events: events.length, notifications: notifications.length,
    escalations: escalations.length,
    consistent: issues.length === 0, issues,
  };
  return { ...canonical, digest: digest(canonical) };
}
export function buildConsistencyReport(
  organizationId: string,
  query: ConsistencyQuery,
  totalTasks: number,
  tasks: ConsistencyTask[],
  events: ConsistencyEvent[],
  notifications: ConsistencyNotification[],
  escalations: ConsistencyEscalation[],
  now: Date,
  truncated: boolean,
): ConsistencyReport {
  const byTask = <T extends { taskId: string }>(rows: T[]) => {
    const result = new Map<string, T[]>();
    for (const row of rows) {
      const bucket = result.get(row.taskId) ?? [];
      bucket.push(row);
      result.set(row.taskId, bucket);
    }
    return result;
  };
  const eventMap = byTask(events);
  const notificationMap = byTask(notifications);
  const escalationMap = byTask(escalations);
  const reports = tasks.map(task => inspectConsistencyTask(
    task, eventMap.get(task.id) ?? [],
    notificationMap.get(task.id) ?? [],
    escalationMap.get(task.id) ?? [],
  ));
  const issueCounts: ConsistencyReport["issueCounts"] = {};
  for (const report of reports)
    for (const issue of report.issues)
      issueCounts[issue.code] = (issueCounts[issue.code] ?? 0) + 1;
  const canonical = {
    schema: "cyberpilot.integrity.workflow.consistency.v1" as const,
    organizationId, captureId: query.captureId ?? null,
    offset: query.offset, limit: query.limit,
    totalTasks,
    hasMore: query.offset + tasks.length < totalTasks,
    complete: !truncated,
    scanned: tasks.length,
    consistent: reports.filter(row => row.consistent).length,
    inconsistent: reports.filter(row => !row.consistent).length,
    issueCounts, tasks: reports,
  };
  return {
    ...canonical, generatedAt: now.toISOString(),
    digest: digest(canonical),
    limitations: [
      "This is a read-only operational consistency audit.",
      "Missing or truncated history can create false-positive revision gaps.",
      "No provider verification, security guarantee or automatic repair is implied.",
      "A complete page is not equivalent to a complete organization-wide scan.",
      "Source records are scoped to the authenticated organization.",
    ],
  };
}
export async function readIntegrityConsistencyReport(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Consistency audit requires an administrator.");
  const query = parseConsistencyQuery(value);
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: { id: query.captureId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!capture)
      throw new WorkInputError("MISSING", "Capture not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    ...(query.captureId ? { captureId: query.captureId } : {}),
    ...(query.includeResolved ? {} : {
      completedAt: null,
    }),
  };
  const [totalTasks, tasks] = await Promise.all([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, captureId: true, disposition: true,
        revision: true, ownerUserId: true,
        completedAt: true, createdAt: true, updatedAt: true,
      },
    }),
  ]);
  const ids = tasks.map(task => task.id);
  const relatedWhere = {
    organizationId: scope.organizationId,
    taskId: { in: ids },
  };
  const cap = 10000;
  const [events, notifications, escalations] = ids.length ?
    await Promise.all([
      db.integrityReviewEvent.findMany({
        where: relatedWhere, take: cap,
        orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true,
          revisionBefore: true, revisionAfter: true,
          before: true, after: true, action: true, occurredAt: true,
        },
      }),
      db.integrityNotification.findMany({
        where: relatedWhere, take: cap,
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, recipientUserId: true,
          kind: true, revision: true, createdAt: true,
          readAt: true, dismissedAt: true,
        },
      }),
      db.integrityEscalation.findMany({
        where: relatedWhere, take: cap,
        orderBy: [{ openedAt: "asc" }, { id: "asc" }],
        select: {
          id: true, taskId: true, state: true, level: true,
          revision: true, openedAt: true, dueAt: true,
          acknowledgedAt: true, resolvedAt: true,
        },
      }),
    ]) : [[], [], []];
  return buildConsistencyReport(
    scope.organizationId, query, totalTasks, tasks,
    events, notifications, escalations, now,
    events.length >= cap || notifications.length >= cap ||
      escalations.length >= cap,
  );
}
