import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Administrative investigation of committed intervention audit trails.
 * No audit metadata is trusted as proof that a security control passed.
 */
export type InterventionHistoryQuery = {
  captureId: string;
  taskId?: string;
  action?: "ASSIGN" | "UNASSIGN" | "NOTIFY_OWNER" |
    "NOTIFY_ADMINS" | "SET_DUE_REMINDER" | "CLEAR_DUE_REMINDER";
  from?: Date;
  to?: Date;
  offset: number;
  limit: number;
};
export type InterventionAuditSource = {
  id: string;
  action: string;
  resourceId: string | null;
  actorUserId: string | null;
  occurredAt: Date;
  metadata: unknown;
};
export type InterventionAuditEntry = {
  eventId: string;
  taskId: string;
  action: string;
  timestamp: string;
  actorHash: string | null;
  idempotencyHash: string | null;
  beforeRevision: number | null;
  afterRevision: number | null;
  previousOwnerHash: string | null;
  nextOwnerHash: string | null;
  recipientCount: number | null;
  notificationCount: number | null;
  noteDigest: string | null;
  replayKeySeen: boolean;
  anomalies: string[];
  fingerprint: string;
};
export type InterventionHistoryGroup = {
  taskId: string;
  actions: number;
  distinctActors: number;
  assignments: number;
  unassignments: number;
  notices: number;
  notifications: number;
  duplicateKeys: number;
  anomalies: number;
  firstActionAt: string;
  lastActionAt: string;
};
export type InterventionHistoryReport = {
  schema: "cyberpilot.integrity.intervention.history.v1";
  organizationId: string;
  captureId: string;
  taskId: string | null;
  generatedAt: string;
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
  complete: boolean;
  entries: InterventionAuditEntry[];
  groups: InterventionHistoryGroup[];
  anomalyCounts: Record<string, number>;
  actionCounts: Record<string, number>;
  digest: string;
  limitations: string[];
};
const allowedActions = [
  "assign", "unassign", "notify_owner", "notify_admins",
  "set_due_reminder", "clear_due_reminder",
] as const;
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected history filter.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid history " + label + ".");
  return value;
}
function date(value: unknown) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    throw new WorkInputError("INVALID", "History date must be UTC ISO8601.");
  const result = new Date(value);
  if (!Number.isFinite(result.getTime()) || result.toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid history date.");
  return result;
}
export function parseInterventionHistoryQuery(value: unknown): InterventionHistoryQuery {
  const raw = object(value);
  const allowed = ["captureId", "taskId", "action", "from",
    "to", "offset", "limit"];
  if (Object.keys(raw).some(key => !allowed.includes(key)))
    throw new WorkInputError("INVALID", "Unknown history filter.");
  if (raw.action !== undefined &&
      !allowedActions.includes(String(raw.action).toLowerCase() as typeof allowedActions[number]))
    throw new WorkInputError("INVALID", "Unsupported triage action.");
  const from = raw.from === undefined ? undefined : date(raw.from);
  const to = raw.to === undefined ? undefined : date(raw.to);
  if (from && to && from >= to)
    throw new WorkInputError("INVALID", "From must precede to.");
  if (from && to && to.getTime() - from.getTime() > 366 * 86400000)
    throw new WorkInputError("INVALID", "History range must be at most 366 days.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    ...(raw.taskId === undefined ? {} : {
      taskId: parseWorkId(raw.taskId, "review task ID"),
    }),
    ...(raw.action === undefined ? {} : {
      action: String(raw.action).toUpperCase() as
      NonNullable<InterventionHistoryQuery["action"]>,
    }),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
  };
}
export function interventionHistoryDigest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function metadata(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ?
    value as Record<string, unknown> : {};
}
function string(value: unknown) {
  return typeof value === "string" && value.length > 0 ? value : null;
}
function count(value: unknown) {
  return typeof value === "number" && Number.isSafeInteger(value) &&
    value >= 0 ? value : null;
}
export function mapInterventionAuditEvent(
  event: InterventionAuditSource,
  previousKeys: Set<string>,
): InterventionAuditEntry {
  const data = metadata(event.metadata);
  const anomalies: string[] = [];
  const key = string(data.idempotencyKey);
  const previous = string(data.previousOwner);
  const next = string(data.nextOwner);
  const before = count(data.revisionBefore);
  const after = count(data.revisionAfter);
  const notificationCount = count(data.notificationCount);
  const recipientCount = count(data.recipientCount);
  const replayKeySeen = Boolean(key && previousKeys.has(key));
  if (!key || !key.startsWith("triage:"))
    anomalies.push("MISSING_OR_INVALID_IDEMPOTENCY_KEY");
  if (replayKeySeen) anomalies.push("DUPLICATE_AUDIT_KEY_ON_PAGE");
  if (before === null || after === null)
    anomalies.push("INVALID_REVIEW_REVISION");
  else if (after !== before)
    anomalies.push("TRIAGE_CHANGED_REVIEW_REVISION");
  if (notificationCount === null || recipientCount === null)
    anomalies.push("MISSING_DELIVERY_COUNTS");
  if (event.action === "integrity.triage.assign" && !next)
    anomalies.push("ASSIGNMENT_MISSING_TARGET");
  if (event.action === "integrity.triage.unassign" && next)
    anomalies.push("UNASSIGNMENT_TARGET_NOT_NULL");
  if (event.action === "integrity.triage.unassign" && !previous)
    anomalies.push("UNASSIGNMENT_MISSING_SOURCE");
  const note = string(data.note);
  if (!note) anomalies.push("MISSING_AUDIT_REASON");
  if (!event.actorUserId) anomalies.push("MISSING_ACTOR");
  if (!event.resourceId) anomalies.push("MISSING_TASK_REFERENCE");
  if (key) previousKeys.add(key);
  const canonical = {
    eventId: event.id, taskId: event.resourceId ?? "",
    action: event.action, timestamp: event.occurredAt.toISOString(),
    actorHash: event.actorUserId ?
      interventionHistoryDigest(event.actorUserId) : null,
    idempotencyHash: key ? interventionHistoryDigest(key) : null,
    beforeRevision: before, afterRevision: after,
    previousOwnerHash: previous ? interventionHistoryDigest(previous) : null,
    nextOwnerHash: next ? interventionHistoryDigest(next) : null,
    recipientCount, notificationCount,
    noteDigest: note ? interventionHistoryDigest(note) : null,
    replayKeySeen, anomalies,
  };
  return { ...canonical, fingerprint: interventionHistoryDigest(canonical) };
}
export function groupInterventionHistory(
  entries: InterventionAuditEntry[],
): InterventionHistoryGroup[] {
  const groups = new Map<string, InterventionAuditEntry[]>();
  for (const entry of entries) {
    const items = groups.get(entry.taskId) ?? [];
    items.push(entry);
    groups.set(entry.taskId, items);
  }
  return [...groups.entries()].map(([taskId, events]) => ({
    taskId, actions: events.length,
    distinctActors: new Set(events.map(x => x.actorHash).filter(Boolean)).size,
    assignments: events.filter(x => x.action.endsWith(".assign")).length,
    unassignments: events.filter(x => x.action.endsWith(".unassign")).length,
    notices: events.filter(x => x.action.includes("notify_") ||
      x.action.includes("reminder")).length,
    notifications: events.reduce((sum, x) => sum + (x.notificationCount ?? 0), 0),
    duplicateKeys: events.filter(x => x.replayKeySeen).length,
    anomalies: events.reduce((sum, x) => sum + x.anomalies.length, 0),
    firstActionAt: events.map(x => x.timestamp).sort()[0]!,
    lastActionAt: events.map(x => x.timestamp).sort().at(-1)!,
  })).sort((a, b) => b.anomalies - a.anomalies ||
    b.actions - a.actions || a.taskId.localeCompare(b.taskId));
}
export function buildInterventionHistoryReport(
  organizationId: string, query: InterventionHistoryQuery,
  events: InterventionAuditSource[], total: number, now: Date,
): InterventionHistoryReport {
  const keys = new Set<string>();
  const entries = events.map(event => mapInterventionAuditEvent(event, keys));
  const anomalyCounts: Record<string, number> = {};
  const actionCounts: Record<string, number> = {};
  for (const entry of entries) {
    actionCounts[entry.action] = (actionCounts[entry.action] ?? 0) + 1;
    for (const issue of entry.anomalies)
      anomalyCounts[issue] = (anomalyCounts[issue] ?? 0) + 1;
  }
  const groups = groupInterventionHistory(entries);
  const canonical = {
    schema: "cyberpilot.integrity.intervention.history.v1" as const,
    organizationId, captureId: query.captureId,
    taskId: query.taskId ?? null,
    generatedAt: now.toISOString(),
    offset: query.offset, limit: query.limit, total,
    hasMore: query.offset + events.length < total,
    complete: query.offset === 0 && events.length === total,
    entries, groups, anomalyCounts, actionCounts,
  };
  return {
    ...canonical,
    digest: interventionHistoryDigest(canonical),
    limitations: [
      "History summarizes durable audit events, not independently verified controls.",
      "Actor and owner hashes are pseudonymous and may still be linkable.",
      "Duplicate-key detection covers this page only and can miss records on other pages.",
      "Historical recipient counts do not prove human attention or external delivery.",
      "Replays do not create a second audit event; this report cannot count replay calls.",
      "No operational review dispositions, remediation or CyberScore are modified.",
    ],
  };
}
export async function readInterventionHistory(
  scope: ReviewScope, value: unknown, now = new Date(),
): Promise<InterventionHistoryReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Intervention history requires administrator access.");
  const query = parseInterventionHistoryQuery(value);
  const capture = await db.integrityCaseCapture.findFirst({
    where: { id: query.captureId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!capture) throw new WorkInputError("MISSING", "Capture not found.");
  if (query.taskId) {
    const task = await db.integrityReviewTask.findFirst({
      where: {
        id: query.taskId, captureId: query.captureId,
        organizationId: scope.organizationId,
      },
      select: { id: true },
    });
    if (!task) throw new WorkInputError("MISSING", "Review task not found.");
  }
  const relevant = await db.integrityReviewTask.findMany({
    where: {
      organizationId: scope.organizationId,
      captureId: query.captureId,
      ...(query.taskId ? { id: query.taskId } : {}),
    },
    select: { id: true },
    take: 10001,
  });
  if (relevant.length > 10000)
    throw new WorkInputError("INVALID",
      "Capture exceeds the safe audit investigation size; filter to one task.");
  const ids = relevant.map(task => task.id);
  const where = {
    organizationId: scope.organizationId,
    resourceType: "IntegrityReviewTask",
    resourceId: { in: ids },
    action: query.action ?
      { equals: "integrity.triage." + query.action.toLowerCase() } :
      { startsWith: "integrity.triage." },
    ...(query.from || query.to ? {
      occurredAt: {
        ...(query.from ? { gte: query.from } : {}),
        ...(query.to ? { lt: query.to } : {}),
      },
    } : {}),
  };
  const [total, events] = await db.$transaction([
    db.auditEvent.count({ where }),
    db.auditEvent.findMany({
      where, skip: query.offset, take: query.limit,
      orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
      select: {
        id: true, action: true, resourceId: true,
        actorUserId: true, occurredAt: true, metadata: true,
      },
    }),
  ]);
  return buildInterventionHistoryReport(
    scope.organizationId, query, events, total, now);
}
