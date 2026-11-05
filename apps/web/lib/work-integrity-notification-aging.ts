import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * In-app inbox aging and concentration diagnostics. Read-only, scoped to an
 * organization; recipient identifiers are never emitted in clear text.
 */
export type AgingQuery = {
  captureId?: string;
  minAgeHours: number;
  maxAgeDays: number;
  limit: number;
  offset: number;
  includeDismissed: boolean;
  includeRead: boolean;
  groupBy: "KIND" | "RECIPIENT" | "TASK" | "AGE_BUCKET";
};
export type AgingNotification = {
  id: string;
  taskId: string;
  recipientUserId: string;
  kind: string;
  createdAt: Date;
  readAt: Date | null;
  dismissedAt: Date | null;
  revision: number;
};
export type AgingRecord = {
  id: string;
  taskId: string;
  recipientHash: string;
  kind: string;
  createdAt: string;
  ageHours: number;
  ageBucket: "UNDER_1_DAY" | "ONE_TO_THREE_DAYS" |
    "THREE_TO_SEVEN_DAYS" | "OVER_SEVEN_DAYS";
  state: "UNREAD" | "READ" | "DISMISSED";
  revision: number;
  anomalies: string[];
  fingerprint: string;
};
export type AgingBucket = {
  key: string;
  count: number;
  unread: number;
  read: number;
  dismissed: number;
  olderThan24Hours: number;
  olderThan72Hours: number;
  olderThan7Days: number;
  maxAgeHours: number;
  medianAgeHours: number;
  distinctTasks: number;
  distinctRecipients: number;
  anomalies: number;
};
export type AgingReport = {
  schema: "cyberpilot.integrity.notification.aging.v1";
  organizationId: string;
  captureId: string | null;
  generatedAt: string;
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
  groupBy: AgingQuery["groupBy"];
  records: AgingRecord[];
  buckets: AgingBucket[];
  digest: string;
  warnings: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected inbox aging query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseAgingQuery(value: unknown): AgingQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "minAgeHours", "maxAgeDays", "limit", "offset",
    "includeDismissed", "includeRead", "groupBy",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown inbox aging field.");
  for (const flag of ["includeDismissed", "includeRead"])
    if (raw[flag] !== undefined && typeof raw[flag] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid " + flag + ".");
  const groupBy = raw.groupBy ?? "AGE_BUCKET";
  if (!["KIND", "RECIPIENT", "TASK", "AGE_BUCKET"].includes(String(groupBy)))
    throw new WorkInputError("INVALID", "Invalid aging grouping.");
  const minAgeHours = integer(raw.minAgeHours ?? 0, "minAgeHours", 0, 8760);
  const maxAgeDays = integer(raw.maxAgeDays ?? 365, "maxAgeDays", 1, 366);
  if (minAgeHours >= maxAgeDays * 24)
    throw new WorkInputError("INVALID", "Minimum age must be below maximum age.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    minAgeHours, maxAgeDays,
    limit: integer(raw.limit ?? 100, "limit", 1, 500),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    includeDismissed: raw.includeDismissed === true,
    includeRead: raw.includeRead === true,
    groupBy: groupBy as AgingQuery["groupBy"],
  };
}
export function agingBucket(hours: number): AgingRecord["ageBucket"] {
  if (hours < 24) return "UNDER_1_DAY";
  if (hours < 72) return "ONE_TO_THREE_DAYS";
  if (hours < 168) return "THREE_TO_SEVEN_DAYS";
  return "OVER_SEVEN_DAYS";
}
export function mapAgingNotification(
  record: AgingNotification, now: Date,
): AgingRecord {
  const ageHours = Math.max(0,
    (now.getTime() - record.createdAt.getTime()) / 3600000);
  const anomalies: string[] = [];
  if (record.createdAt > now) anomalies.push("FUTURE_CREATION");
  if (record.readAt && record.readAt < record.createdAt)
    anomalies.push("READ_BEFORE_CREATION");
  if (record.dismissedAt && record.dismissedAt < record.createdAt)
    anomalies.push("DISMISSED_BEFORE_CREATION");
  if (!Number.isSafeInteger(record.revision) || record.revision < 1)
    anomalies.push("INVALID_REVISION");
  const state: AgingRecord["state"] = record.dismissedAt ? "DISMISSED" :
    record.readAt ? "READ" : "UNREAD";
  const canonical = {
    id: record.id, taskId: record.taskId,
    recipientHash: sha(record.recipientUserId),
    kind: record.kind, createdAt: record.createdAt.toISOString(),
    ageHours: Math.round(ageHours * 100) / 100,
    ageBucket: agingBucket(ageHours),
    state, revision: record.revision, anomalies,
  };
  return {
    ...canonical, fingerprint: sha(canonical),
  };
}
function median(values: number[]) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ?
    sorted[middle]! :
    (sorted[middle - 1]! + sorted[middle]!) / 2;
}
export function buildAgingReport(
  organizationId: string,
  query: AgingQuery,
  records: AgingNotification[],
  total: number,
  now: Date,
): AgingReport {
  const mapped = records.map(row => mapAgingNotification(row, now));
  const groups = new Map<string, AgingRecord[]>();
  for (const record of mapped) {
    const key = query.groupBy === "KIND" ? record.kind :
      query.groupBy === "RECIPIENT" ? record.recipientHash :
      query.groupBy === "TASK" ? record.taskId : record.ageBucket;
    const rows = groups.get(key) ?? [];
    rows.push(record);
    groups.set(key, rows);
  }
  const buckets: AgingBucket[] = [];
  for (const [key, rows] of groups) {
    buckets.push({
      key, count: rows.length,
      unread: rows.filter(row => row.state === "UNREAD").length,
      read: rows.filter(row => row.state === "READ").length,
      dismissed: rows.filter(row => row.state === "DISMISSED").length,
      olderThan24Hours: rows.filter(row => row.ageHours >= 24).length,
      olderThan72Hours: rows.filter(row => row.ageHours >= 72).length,
      olderThan7Days: rows.filter(row => row.ageHours >= 168).length,
      maxAgeHours: Math.max(...rows.map(row => row.ageHours)),
      medianAgeHours: Math.round(median(rows.map(row => row.ageHours)) * 100) / 100,
      distinctTasks: new Set(rows.map(row => row.taskId)).size,
      distinctRecipients: new Set(rows.map(row => row.recipientHash)).size,
      anomalies: rows.reduce((n, row) => n + row.anomalies.length, 0),
    });
  }
  buckets.sort((a, b) =>
    b.unread - a.unread || b.maxAgeHours - a.maxAgeHours ||
    a.key.localeCompare(b.key));
  const canonical = {
    schema: "cyberpilot.integrity.notification.aging.v1" as const,
    organizationId, captureId: query.captureId ?? null,
    generatedAt: now.toISOString(),
    offset: query.offset, limit: query.limit, total,
    hasMore: query.offset + records.length < total,
    groupBy: query.groupBy, records: mapped, buckets,
  };
  return {
    ...canonical, digest: sha(canonical),
    warnings: [
      "Aging is based on persisted in-app timestamps only.",
      "Read status does not prove human attention or external delivery.",
      "Recipient identifiers are SHA-256 pseudonyms, not anonymous identities.",
      "Bucket statistics cover this page only, not the entire inbox.",
      "Historical notification age is not a measure of security posture.",
    ],
  };
}
export async function readIntegrityNotificationAging(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Inbox aging requires administrator access.");
  const query = parseAgingQuery(value);
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
    createdAt: {
      gte: new Date(now.getTime() - query.maxAgeDays * 86400000),
      lte: new Date(now.getTime() - query.minAgeHours * 3600000),
    },
    ...(query.includeDismissed ? {} : { dismissedAt: null }),
    ...(query.includeRead ? {} : { readAt: null }),
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
      where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, taskId: true, recipientUserId: true,
        kind: true, createdAt: true, readAt: true,
        dismissedAt: true, revision: true,
      },
    }),
  ]);
  return buildAgingReport(
    scope.organizationId, query, records, total, now,
  );
}
