import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Administrative notification delivery diagnostics. All statistics refer to
 * persisted in-app state; no claim is made about external delivery or a
 * recipient reading content outside the app.
 */
export type DeliveryDiagnosticsQuery = {
  captureId?: string;
  from: Date;
  to: Date;
  groupBy: "KIND" | "TASK" | "RECIPIENT";
  limit: number;
  includeDismissed: boolean;
};
export type DeliveryRecord = {
  id: string;
  taskId: string;
  recipientUserId: string;
  kind: string;
  createdAt: Date;
  readAt: Date | null;
  dismissedAt: Date | null;
  revision: number;
};
export type DeliveryBucket = {
  key: string;
  total: number;
  unread: number;
  read: number;
  dismissed: number;
  readWithin24Hours: number;
  readAfter24Hours: number;
  medianReadMinutes: number | null;
  oldestUnreadAt: string | null;
  newestAt: string | null;
  recipientCount: number;
  taskCount: number;
  revisionAnomalies: number;
};
export type DeliveryDiagnostics = {
  from: string;
  to: string;
  groupBy: DeliveryDiagnosticsQuery["groupBy"];
  total: number;
  scanned: number;
  truncated: boolean;
  buckets: DeliveryBucket[];
  summary: {
    total: number;
    unread: number;
    read: number;
    dismissed: number;
    readWithin24Hours: number;
    oldestUnreadAt: string | null;
    uniqueRecipients: number;
    uniqueTasks: number;
  };
  digest: string;
  limitations: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected delivery diagnostics query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
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
export function parseDeliveryDiagnosticsQuery(
  value: unknown, now = new Date(),
): DeliveryDiagnosticsQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "from", "to", "groupBy", "limit",
    "includeDismissed",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown diagnostics field.");
  const to = raw.to === undefined ? now : date(raw.to, "to");
  const from = raw.from === undefined ?
    new Date(to.getTime() - 30 * 86400000) : date(raw.from, "from");
  if (from.getTime() >= to.getTime() ||
      to.getTime() - from.getTime() > 366 * 86400000)
    throw new WorkInputError("INVALID", "Diagnostics range must be 1–366 days.");
  if (raw.groupBy !== undefined &&
      !["KIND", "TASK", "RECIPIENT"].includes(String(raw.groupBy)))
    throw new WorkInputError("INVALID", "Invalid diagnostics grouping.");
  if (raw.includeDismissed !== undefined &&
      typeof raw.includeDismissed !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dismissed flag.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    from, to,
    groupBy: (raw.groupBy ?? "KIND") as DeliveryDiagnosticsQuery["groupBy"],
    limit: integer(raw.limit ?? 10000, "limit", 1, 20000),
    includeDismissed: raw.includeDismissed !== false,
  };
}
function median(values: number[]) {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  const center = Math.floor(ordered.length / 2);
  if (ordered.length % 2 === 1) return ordered[center] ?? null;
  return ((ordered[center - 1] ?? 0) + (ordered[center] ?? 0)) / 2;
}
export function rollupDeliveryDiagnostics(
  query: DeliveryDiagnosticsQuery,
  records: DeliveryRecord[],
  total: number,
): DeliveryDiagnostics {
  const grouped = new Map<string, DeliveryRecord[]>();
  const sorted = [...records].sort((a, b) =>
    a.createdAt.getTime() - b.createdAt.getTime() ||
    a.id.localeCompare(b.id));
  for (const record of sorted) {
    const key = query.groupBy === "TASK" ? record.taskId :
      query.groupBy === "RECIPIENT" ?
        createHash("sha256").update(record.recipientUserId).digest("hex") :
        record.kind;
    const current = grouped.get(key) ?? [];
    current.push(record);
    grouped.set(key, current);
  }
  const buckets: DeliveryBucket[] = [];
  for (const [key, rows] of grouped) {
    const reads = rows.flatMap(row =>
      row.readAt && row.readAt >= row.createdAt ?
        [(row.readAt.getTime() - row.createdAt.getTime()) / 60000] : []);
    const unreadRows = rows.filter(row => !row.readAt && !row.dismissedAt);
    const oldest = unreadRows.map(row => row.createdAt.getTime());
    buckets.push({
      key,
      total: rows.length,
      unread: unreadRows.length,
      read: rows.filter(row => row.readAt !== null).length,
      dismissed: rows.filter(row => row.dismissedAt !== null).length,
      readWithin24Hours: reads.filter(minutes => minutes <= 1440).length,
      readAfter24Hours: reads.filter(minutes => minutes > 1440).length,
      medianReadMinutes: median(reads),
      oldestUnreadAt: oldest.length ?
        new Date(Math.min(...oldest)).toISOString() : null,
      newestAt: rows.length ?
        rows[rows.length - 1]!.createdAt.toISOString() : null,
      recipientCount: new Set(rows.map(row => row.recipientUserId)).size,
      taskCount: new Set(rows.map(row => row.taskId)).size,
      revisionAnomalies: rows.filter(row =>
        !Number.isSafeInteger(row.revision) || row.revision < 1 ||
        (row.readAt !== null && row.readAt < row.createdAt) ||
        (row.dismissedAt !== null && row.dismissedAt < row.createdAt),
      ).length,
    });
  }
  buckets.sort((a, b) =>
    b.unread - a.unread || b.total - a.total || a.key.localeCompare(b.key));
  const unread = sorted.filter(row => !row.readAt && !row.dismissedAt);
  const readWithin24Hours = sorted.filter(row =>
    row.readAt && row.readAt >= row.createdAt &&
    row.readAt.getTime() - row.createdAt.getTime() <= 86400000).length;
  const summary = {
    total: sorted.length,
    unread: unread.length,
    read: sorted.filter(row => row.readAt !== null).length,
    dismissed: sorted.filter(row => row.dismissedAt !== null).length,
    readWithin24Hours,
    oldestUnreadAt: unread.length ?
      unread[0]!.createdAt.toISOString() : null,
    uniqueRecipients: new Set(sorted.map(row => row.recipientUserId)).size,
    uniqueTasks: new Set(sorted.map(row => row.taskId)).size,
  };
  const digest = createHash("sha256").update(JSON.stringify({
    from: query.from.toISOString(), to: query.to.toISOString(),
    groupBy: query.groupBy, summary, buckets,
  })).digest("hex");
  return {
    from: query.from.toISOString(), to: query.to.toISOString(),
    groupBy: query.groupBy, total, scanned: sorted.length,
    truncated: sorted.length < total,
    buckets, summary, digest,
    limitations: [
      "Metrics describe stored in-app notifications only.",
      "Read timestamps indicate application state, not confirmed human attention.",
      "Recipients are represented by hashes in grouped diagnostics.",
      "Time-to-read excludes unread records and invalid negative intervals.",
      "Truncated results are partial and cannot represent the whole organization.",
      "The report does not assess provider security or alter CyberScore.",
    ],
  };
}
export async function readIntegrityDeliveryDiagnostics(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Delivery diagnostics require an administrator.");
  const query = parseDeliveryDiagnosticsQuery(value, now);
  if (query.captureId) {
    const capture = await db.integrityCaseCapture.findFirst({
      where: {
        id: query.captureId, organizationId: scope.organizationId,
      },
      select: { id: true },
    });
    if (!capture)
      throw new WorkInputError("MISSING", "Capture not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    createdAt: { gte: query.from, lt: query.to },
    ...(query.includeDismissed ? {} : { dismissedAt: null }),
    ...(query.captureId ? {
      task: {
        organizationId: scope.organizationId,
        captureId: query.captureId,
      },
    } : {}),
  };
  const [total, records] = await Promise.all([
    db.integrityNotification.count({ where }),
    db.integrityNotification.findMany({
      where,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      take: query.limit,
      select: {
        id: true, taskId: true, recipientUserId: true,
        kind: true, createdAt: true, readAt: true,
        dismissedAt: true, revision: true,
      },
    }),
  ]);
  return rollupDeliveryDiagnostics(query, records, total);
}
