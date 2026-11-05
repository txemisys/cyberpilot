import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Independent read-only inspection of in-app notification provenance.
 * A notification without a matching source or creation audit is reported
 * as incomplete, not silently interpreted as verified evidence.
 */
export type NotificationInspectionInput = {
  taskId?: string;
  recipientUserId?: string;
  includeDismissed: boolean;
  offset: number;
  limit: number;
};
export type NotificationIntegrityIssue =
  | "TASK_MISSING"
  | "RECIPIENT_NOT_MEMBER"
  | "SOURCE_NOT_FOUND"
  | "SOURCE_TASK_MISMATCH"
  | "SOURCE_KIND_MISMATCH"
  | "CREATION_AUDIT_MISSING"
  | "AUDIT_TASK_MISMATCH"
  | "AUDIT_RECIPIENT_MISMATCH"
  | "AUDIT_KIND_MISMATCH"
  | "AUDIT_DEDUPE_MISMATCH"
  | "AUDIT_DELIVERY_MISMATCH"
  | "INVALID_REVISION"
  | "DISMISSED_BEFORE_CREATED"
  | "READ_BEFORE_CREATED";
export type NotificationInspectionRow = {
  notificationId: string;
  taskId: string;
  recipientUserId: string;
  kind: string;
  createdAt: string;
  revision: number;
  source: "REVIEW" | "PROVIDER" | "ESCALATION" | "MANUAL" | "UNKNOWN";
  sourceId: string | null;
  auditCount: number;
  issues: NotificationIntegrityIssue[];
  consistent: boolean;
};
export type NotificationInspectionReport = {
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  scanned: number;
  consistent: number;
  inconsistent: number;
  issueCounts: Partial<Record<NotificationIntegrityIssue, number>>;
  rows: NotificationInspectionRow[];
  digest: string;
  limitations: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected notification inspection object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseNotificationInspectionInput(
  value: unknown,
): NotificationInspectionInput {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "taskId", "recipientUserId", "includeDismissed", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown inspection filter.");
  if (raw.includeDismissed !== undefined &&
      typeof raw.includeDismissed !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dismissed filter.");
  return {
    ...(raw.taskId === undefined ? {} : {
      taskId: parseWorkId(raw.taskId, "review task ID"),
    }),
    ...(raw.recipientUserId === undefined ? {} : {
      recipientUserId: parseWorkId(raw.recipientUserId, "recipient user ID"),
    }),
    includeDismissed: raw.includeDismissed === true,
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
  };
}
export type NotificationRecord = {
  id: string; taskId: string; recipientUserId: string;
  kind: string; dedupeKey: string;
  createdAt: Date; readAt: Date | null; dismissedAt: Date | null;
  revision: number; context: unknown;
};
export type NotificationAudit = {
  id: string; resourceId: string; action: string;
  metadata: unknown; occurredAt: Date;
};
export type NotificationSource = {
  id: string; taskId: string;
  kind?: string; after?: string; outcome?: string;
};
function metadata(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ?
    value as Record<string, unknown> : {};
}
export function classifyNotificationSource(
  record: NotificationRecord,
): { source: NotificationInspectionRow["source"]; sourceId: string | null } {
  const context = metadata(record.context);
  if (context.source === "REVIEW_EVENT" &&
      typeof context.sourceId === "string")
    return { source: "REVIEW", sourceId: context.sourceId };
  if (context.source === "PROVIDER_CHECK" &&
      typeof context.sourceId === "string")
    return { source: "PROVIDER", sourceId: context.sourceId };
  if (typeof context.escalationId === "string")
    return { source: "ESCALATION", sourceId: context.escalationId };
  if (record.dedupeKey.startsWith("triage:") ||
      record.dedupeKey.startsWith("assignment-"))
    return { source: "MANUAL", sourceId: null };
  return { source: "UNKNOWN", sourceId: null };
}
export function inspectNotificationRecord(
  record: NotificationRecord,
  audits: NotificationAudit[],
  taskExists: boolean,
  recipientIsMember: boolean,
  source: NotificationSource | null,
): NotificationInspectionRow {
  const issues: NotificationIntegrityIssue[] = [];
  if (!taskExists) issues.push("TASK_MISSING");
  if (!recipientIsMember) issues.push("RECIPIENT_NOT_MEMBER");
  if (record.revision < 1 || !Number.isSafeInteger(record.revision))
    issues.push("INVALID_REVISION");
  if (record.readAt && record.readAt < record.createdAt)
    issues.push("READ_BEFORE_CREATED");
  if (record.dismissedAt && record.dismissedAt < record.createdAt)
    issues.push("DISMISSED_BEFORE_CREATED");
  const provenance = classifyNotificationSource(record);
  if (provenance.sourceId && !source)
    issues.push("SOURCE_NOT_FOUND");
  if (source && source.taskId !== record.taskId)
    issues.push("SOURCE_TASK_MISMATCH");
  if (source && provenance.source === "REVIEW" &&
      (source.after !== "RESOLVED" || record.kind !== "REVIEW_RESOLVED"))
    issues.push("SOURCE_KIND_MISMATCH");
  if (source && provenance.source === "PROVIDER" &&
      ((source.outcome === "PASS" && record.kind !== "PROVIDER_RECOVERED") ||
       (source.outcome === "FAIL" && record.kind !== "PROVIDER_FAILURE") ||
       !["PASS", "FAIL"].includes(source.outcome ?? "")))
    issues.push("SOURCE_KIND_MISMATCH");
  if (source && provenance.source === "ESCALATION" &&
      record.kind !== "REVIEW_ESCALATED")
    issues.push("SOURCE_KIND_MISMATCH");
  const creation = audits.filter(audit => [
    "integrity.notification.published",
    "integrity.notification.dispatched",
    "integrity.notification.event_reconciled",
  ].includes(audit.action));
  // Manual triage creates notification records in the task transaction and
  // audits the triage action on the task, rather than the notification itself.
  if (!creation.length && provenance.source !== "MANUAL")
    issues.push("CREATION_AUDIT_MISSING");
  for (const audit of creation) {
    const data = metadata(audit.metadata);
    if (data.taskId !== record.taskId)
      issues.push("AUDIT_TASK_MISMATCH");
    if (data.recipientUserId !== record.recipientUserId)
      issues.push("AUDIT_RECIPIENT_MISMATCH");
    if (data.kind !== undefined && data.kind !== record.kind)
      issues.push("AUDIT_KIND_MISMATCH");
    if (data.dedupeKey !== undefined &&
        data.dedupeKey !== record.dedupeKey)
      issues.push("AUDIT_DEDUPE_MISMATCH");
    if (data.delivery !== "IN_APP")
      issues.push("AUDIT_DELIVERY_MISMATCH");
  }
  const unique = [...new Set(issues)].sort() as NotificationIntegrityIssue[];
  return {
    notificationId: record.id, taskId: record.taskId,
    recipientUserId: record.recipientUserId,
    kind: record.kind, createdAt: record.createdAt.toISOString(),
    revision: record.revision,
    source: provenance.source, sourceId: provenance.sourceId,
    auditCount: creation.length, issues: unique,
    consistent: unique.length === 0,
  };
}
export function summarizeNotificationInspection(
  rows: NotificationInspectionRow[],
  query: NotificationInspectionInput,
  total: number,
): NotificationInspectionReport {
  const issueCounts: Partial<Record<NotificationIntegrityIssue, number>> = {};
  for (const row of rows)
    for (const issue of row.issues)
      issueCounts[issue] = (issueCounts[issue] ?? 0) + 1;
  const canonical = rows.map(row => ({
    id: row.notificationId,
    taskId: row.taskId,
    recipientUserId: row.recipientUserId,
    revision: row.revision,
    source: row.source,
    sourceId: row.sourceId,
    issues: row.issues,
  }));
  const digest = createHash("sha256")
    .update(JSON.stringify(canonical)).digest("hex");
  return {
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + rows.length < total,
    scanned: rows.length,
    consistent: rows.filter(row => row.consistent).length,
    inconsistent: rows.filter(row => !row.consistent).length,
    issueCounts, rows, digest,
    limitations: [
      "Integrity inspection reports only the selected page.",
      "Historical organization membership is not reconstructed.",
      "A missing audit may reflect legacy notification paths.",
      "An audit record is not proof of delivery outside the application.",
      "This report does not validate the underlying security evidence.",
    ],
  };
}
export async function inspectIntegrityNotifications(
  scope: ReviewScope, value: unknown,
): Promise<NotificationInspectionReport> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Notification inspection denied.");
  const query = parseNotificationInspectionInput(value);
  // Non-admin users may inspect only their own inbox, never another
  // recipient's notification contents or membership information.
  const isAdmin = scope.role === "ADMIN" || scope.role === "OWNER";
  if (!isAdmin && query.recipientUserId &&
      query.recipientUserId !== scope.userId)
    throw new WorkInputError("FORBIDDEN", "Recipient inspection denied.");
  if (query.taskId) {
    const task = await db.integrityReviewTask.findFirst({
      where: { id: query.taskId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!task)
      throw new WorkInputError("MISSING", "Review task not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    ...(isAdmin ?
      (query.recipientUserId ? { recipientUserId: query.recipientUserId } : {}) :
      { recipientUserId: scope.userId }),
    ...(query.taskId ? { taskId: query.taskId } : {}),
    ...(query.includeDismissed ? {} : { dismissedAt: null }),
  };
  const [total, notifications] = await Promise.all([
    db.integrityNotification.count({ where }),
    db.integrityNotification.findMany({
      where, orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, taskId: true, recipientUserId: true,
        kind: true, dedupeKey: true,
        createdAt: true, readAt: true, dismissedAt: true,
        revision: true, context: true,
      },
    }),
  ]);
  const ids = notifications.map(row => row.id);
  const taskIds = [...new Set(notifications.map(row => row.taskId))];
  const recipientIds = [...new Set(notifications.map(row => row.recipientUserId))];
  const provenance = notifications.map(row => classifyNotificationSource(row));
  const reviewIds = provenance.filter(row => row.source === "REVIEW")
    .flatMap(row => row.sourceId ? [row.sourceId] : []);
  const checkIds = provenance.filter(row => row.source === "PROVIDER")
    .flatMap(row => row.sourceId ? [row.sourceId] : []);
  const escalationIds = provenance.filter(row => row.source === "ESCALATION")
    .flatMap(row => row.sourceId ? [row.sourceId] : []);
  const [audits, tasks, memberships, reviews, checks, escalations] =
    await Promise.all([
      db.auditEvent.findMany({
        where: {
          organizationId: scope.organizationId,
          resourceType: "IntegrityNotification",
          resourceId: { in: ids },
        },
        select: {
          id: true, resourceId: true, action: true,
          metadata: true, occurredAt: true,
        },
      }),
      db.integrityReviewTask.findMany({
        where: {
          organizationId: scope.organizationId,
          id: { in: taskIds },
        },
        select: { id: true },
      }),
      db.membership.findMany({
        where: {
          organizationId: scope.organizationId,
          userId: { in: recipientIds },
        },
        select: { userId: true },
      }),
      db.integrityReviewEvent.findMany({
        where: {
          organizationId: scope.organizationId,
          id: { in: reviewIds },
        },
        select: { id: true, taskId: true, after: true },
      }),
      db.integrityProviderCheck.findMany({
        where: {
          organizationId: scope.organizationId,
          id: { in: checkIds },
        },
        select: { id: true, taskId: true, outcome: true },
      }),
      db.integrityEscalation.findMany({
        where: {
          organizationId: scope.organizationId,
          id: { in: escalationIds },
        },
        select: { id: true, taskId: true },
      }),
    ]);
  const auditsByNotification = new Map<string, NotificationAudit[]>();
  for (const audit of audits) {
    if (!audit.resourceId) continue;
    const bucket = auditsByNotification.get(audit.resourceId) ?? [];
    bucket.push({ ...audit, resourceId: audit.resourceId });
    auditsByNotification.set(audit.resourceId, bucket);
  }
  const taskSet = new Set(tasks.map(task => task.id));
  const memberSet = new Set(memberships.map(member => member.userId));
  const sourceMap = new Map<string, NotificationSource>();
  for (const source of [...reviews, ...checks, ...escalations])
    sourceMap.set(source.id, source);
  const rows = notifications.map(record => {
    const ref = classifyNotificationSource(record);
    return inspectNotificationRecord(
      record, auditsByNotification.get(record.id) ?? [],
      taskSet.has(record.taskId),
      memberSet.has(record.recipientUserId),
      ref.sourceId ? sourceMap.get(ref.sourceId) ?? null : null,
    );
  });
  return summarizeNotificationInspection(rows, query, total);
}
