import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";
export type IntegrityNotificationKind =
  | "REVIEW_ASSIGNED" | "REVIEW_OVERDUE" | "REVIEW_ESCALATED"
  | "REVIEW_RESOLVED" | "PROVIDER_FAILURE" | "PROVIDER_RECOVERED";

export type InboxFilter = {
  unreadOnly: boolean;
  includeDismissed: boolean;
  taskId?: string;
  kind?: IntegrityNotificationKind;
  offset: number;
  limit: number;
};
export type NotificationAction = "READ" | "UNREAD" | "DISMISS" | "RESTORE";
export type NotificationCommand = {
  notificationId: string;
  action: NotificationAction;
  expectedRevision: number;
};
export type NotificationPublish = {
  taskId: string;
  recipientUserId: string;
  kind: IntegrityNotificationKind;
  dedupeKey: string;
  title: string;
  message: string;
  context?: Record<string, string | number | boolean | null>;
};
const kinds: IntegrityNotificationKind[] = [
  "REVIEW_ASSIGNED", "REVIEW_OVERDUE", "REVIEW_ESCALATED",
  "REVIEW_RESOLVED", "PROVIDER_FAILURE", "PROVIDER_RECOVERED",
];
const actions: NotificationAction[] = ["READ", "UNREAD", "DISMISS", "RESTORE"];
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected notification object.");
  return value as Record<string, unknown>;
}
function only(raw: Record<string, unknown>, keys: string[]) {
  if (Object.keys(raw).some(key => !keys.includes(key)))
    throw new WorkInputError("INVALID", "Unknown notification parameter.");
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function text(value: unknown, label: string, max: number, min = 1) {
  if (typeof value !== "string" || value.trim().length < min ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value.trim();
}
export function parseInboxFilter(value: unknown): InboxFilter {
  const raw = object(value);
  only(raw, ["unreadOnly", "includeDismissed", "taskId", "kind", "offset", "limit"]);
  for (const flag of ["unreadOnly", "includeDismissed"]) {
    if (raw[flag] !== undefined && typeof raw[flag] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid " + flag + ".");
  }
  if (raw.kind !== undefined && !kinds.includes(raw.kind as IntegrityNotificationKind))
    throw new WorkInputError("INVALID", "Unknown notification kind.");
  return {
    unreadOnly: raw.unreadOnly === true,
    includeDismissed: raw.includeDismissed === true,
    ...(raw.taskId === undefined ? {} : {
      taskId: parseWorkId(raw.taskId, "review task ID"),
    }),
    ...(raw.kind === undefined ? {} : {
      kind: raw.kind as IntegrityNotificationKind,
    }),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
  };
}
export function parseNotificationCommand(value: unknown): NotificationCommand {
  const raw = object(value);
  only(raw, ["notificationId", "action", "expectedRevision"]);
  if (!actions.includes(raw.action as NotificationAction))
    throw new WorkInputError("INVALID", "Unknown notification action.");
  return {
    notificationId: parseWorkId(raw.notificationId, "notification ID"),
    action: raw.action as NotificationAction,
    expectedRevision: integer(raw.expectedRevision, "revision", 1, 2147483646),
  };
}
export function parseNotificationPublish(value: unknown): NotificationPublish {
  const raw = object(value);
  only(raw, ["taskId", "recipientUserId", "kind", "dedupeKey", "title", "message", "context"]);
  if (!kinds.includes(raw.kind as IntegrityNotificationKind))
    throw new WorkInputError("INVALID", "Unknown notification kind.");
  const context: Record<string, string | number | boolean | null> = {};
  if (raw.context !== undefined) {
    const source = object(raw.context);
    if (Object.keys(source).length > 20)
      throw new WorkInputError("INVALID", "Notification context too large.");
    for (const [key, val] of Object.entries(source)) {
      if (!/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key) ||
          (val !== null && typeof val !== "string" &&
            typeof val !== "number" && typeof val !== "boolean") ||
          (typeof val === "string" && val.length > 500) ||
          (typeof val === "number" && !Number.isFinite(val)))
        throw new WorkInputError("INVALID", "Invalid notification context.");
      context[key] = val as string | number | boolean | null;
    }
  }
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    recipientUserId: parseWorkId(raw.recipientUserId, "recipient user ID"),
    kind: raw.kind as IntegrityNotificationKind,
    dedupeKey: text(raw.dedupeKey, "deduplication key", 180, 8),
    title: text(raw.title, "title", 200),
    message: text(raw.message, "message", 2000),
    ...(raw.context === undefined ? {} : { context }),
  };
}
export function notificationFingerprint(value: NotificationPublish) {
  return createHash("sha256").update(JSON.stringify({
    taskId: value.taskId, recipientUserId: value.recipientUserId,
    kind: value.kind, dedupeKey: value.dedupeKey,
    title: value.title, message: value.message,
    context: value.context ?? {},
  })).digest("hex");
}
export async function listInbox(scope: ReviewScope, value: unknown) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Notification inbox denied.");
  const query = parseInboxFilter(value);
  const where = {
    organizationId: scope.organizationId,
    recipientUserId: scope.userId,
    ...(query.unreadOnly ? { readAt: null } : {}),
    ...(query.includeDismissed ? {} : { dismissedAt: null }),
    ...(query.taskId ? { taskId: query.taskId } : {}),
    ...(query.kind ? { kind: query.kind } : {}),
  };
  const [total, unread, notifications] = await db.$transaction([
    db.integrityNotification.count({ where }),
    db.integrityNotification.count({
      where: { ...where, readAt: null },
    }),
    db.integrityNotification.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
    }),
  ]);
  return {
    total, unread, offset: query.offset, limit: query.limit,
    hasMore: query.offset + notifications.length < total,
    notifications,
    delivery: "IN_APP",
    limitations: [
      "Notifications are delivered to the in-app inbox only.",
      "Read and dismissal state is private to the recipient.",
    ],
  };
}
export async function publishNotification(
  scope: ReviewScope, value: unknown,
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Publishing requires an administrator.");
  const input = parseNotificationPublish(value);
  return db.$transaction(async tx => {
    const [task, membership] = await Promise.all([
      tx.integrityReviewTask.findFirst({
        where: { id: input.taskId, organizationId: scope.organizationId },
        select: { id: true, disposition: true },
      }),
      tx.membership.findFirst({
        where: {
          organizationId: scope.organizationId,
          userId: input.recipientUserId,
        },
        select: { id: true },
      }),
    ]);
    if (!task || !membership)
      throw new WorkInputError("MISSING", "Task or recipient not found.");
    const existing = await tx.integrityNotification.findUnique({
      where: {
        organizationId_recipientUserId_dedupeKey: {
          organizationId: scope.organizationId,
          recipientUserId: input.recipientUserId,
          dedupeKey: input.dedupeKey,
        },
      },
    });
    if (existing) {
      if (existing.taskId !== input.taskId ||
          existing.kind !== input.kind ||
          existing.title !== input.title ||
          existing.message !== input.message ||
          JSON.stringify(existing.context ?? {}) !== JSON.stringify(input.context ?? {}))
        throw new WorkInputError("CONFLICT", "Notification key reused with different content.");
      return { notification: existing, replayed: true };
    }
    const notification = await tx.integrityNotification.create({
      data: {
        organizationId: scope.organizationId,
        taskId: input.taskId,
        recipientUserId: input.recipientUserId,
        kind: input.kind, dedupeKey: input.dedupeKey,
        title: input.title, message: input.message,
        context: input.context ?? {},
      },
    });
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "integrity.notification.published",
        resourceType: "IntegrityNotification",
        resourceId: notification.id,
        metadata: {
          taskId: input.taskId, recipientUserId: input.recipientUserId,
          kind: input.kind, dedupeKey: input.dedupeKey,
          fingerprint: notificationFingerprint(input),
          delivery: "IN_APP",
        },
      },
    });
    return { notification, replayed: false };
  });
}
export async function updateInboxNotification(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Notification update denied.");
  const input = parseNotificationCommand(value);
  return db.$transaction(async tx => {
    const current = await tx.integrityNotification.findFirst({
      where: {
        id: input.notificationId,
        organizationId: scope.organizationId,
        recipientUserId: scope.userId,
      },
    });
    if (!current)
      throw new WorkInputError("MISSING", "Notification not found.");
    if (current.revision !== input.expectedRevision)
      throw new WorkInputError("CONFLICT", "Notification revision changed.");
    const patch = input.action === "READ" ? { readAt: now } :
      input.action === "UNREAD" ? { readAt: null } :
      input.action === "DISMISS" ? { dismissedAt: now } :
      { dismissedAt: null };
    if ((input.action === "READ" && current.readAt) ||
        (input.action === "UNREAD" && !current.readAt) ||
        (input.action === "DISMISS" && current.dismissedAt) ||
        (input.action === "RESTORE" && !current.dismissedAt))
      throw new WorkInputError("CONFLICT", "Notification already in requested state.");
    const changed = await tx.integrityNotification.updateMany({
      where: {
        id: current.id, organizationId: scope.organizationId,
        recipientUserId: scope.userId, revision: current.revision,
      },
      data: { ...patch, revision: { increment: 1 } },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT", "Concurrent notification update.");
    const notification = await tx.integrityNotification.findUniqueOrThrow({
      where: { id: current.id },
    });
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "integrity.notification." + input.action.toLowerCase(),
        resourceType: "IntegrityNotification", resourceId: current.id,
        metadata: {
          taskId: current.taskId, revisionBefore: current.revision,
          revisionAfter: notification.revision,
        },
      },
    });
    return { notification };
  });
}
export async function countInboxByKind(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Notification counters denied.");
  const groups = await db.integrityNotification.groupBy({
    by: ["kind"],
    where: {
      organizationId: scope.organizationId,
      recipientUserId: scope.userId,
      readAt: null, dismissedAt: null,
    },
    _count: { id: true },
  });
  const counts = Object.fromEntries(kinds.map(kind => [kind, 0])) as
    Record<IntegrityNotificationKind, number>;
  for (const group of groups) counts[group.kind] = group._count.id;
  return {
    counts, unread: Object.values(counts).reduce((a, b) => a + b, 0),
  };
}
