import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Read-only operational queue. Never infer provider verification from a
 * human review disposition or from a completed work item.
 */
export type QueueBucket =
  | "OVERDUE" | "DUE_SOON" | "UNASSIGNED" | "IN_PROGRESS"
  | "AWAITING_REVIEW" | "COMPLETED" | "WAIVED";
export type QueueSort = "OLDEST" | "NEWEST" | "SEVERITY" | "DEADLINE";
export type QueueQuery = {
  captureId?: string;
  bucket?: QueueBucket;
  severity?: "ERROR" | "WARNING" | "INFO";
  assignedTo?: string;
  sort: QueueSort;
  offset: number;
  limit: number;
  warningHours: number;
  errorHours: number;
  infoHours: number;
  soonHours: number;
};
export type QueueTask = {
  taskId: string;
  captureId: string;
  externalTaskId: string;
  title: string;
  severity: string;
  disposition: string;
  required: boolean;
  ownerUserId: string | null;
  createdAt: string;
  updatedAt: string;
  dueAt: string;
  overdueMinutes: number;
  bucket: QueueBucket;
  urgency: number;
  escalation: {
    id: string;
    state: string;
    level: number;
    openedAt: string;
  } | null;
  notifications: {
    total: number;
    unreadForCurrentUser: number;
  };
  work: {
    linked: number;
    active: number;
  };
  evidence: {
    assessments: number;
    providerChecks: number;
    latestProviderOutcome: string | null;
    latestProviderCheckedAt: string | null;
  };
  flags: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected queue query object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
const buckets: QueueBucket[] = [
  "OVERDUE", "DUE_SOON", "UNASSIGNED", "IN_PROGRESS",
  "AWAITING_REVIEW", "COMPLETED", "WAIVED",
];
const sorts: QueueSort[] = ["OLDEST", "NEWEST", "SEVERITY", "DEADLINE"];
const severities = ["ERROR", "WARNING", "INFO"];
export function parseQueueQuery(value: unknown): QueueQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "bucket", "severity", "assignedTo", "sort",
    "offset", "limit", "warningHours", "errorHours",
    "infoHours", "soonHours",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown queue filter.");
  if (raw.bucket !== undefined && !buckets.includes(raw.bucket as QueueBucket))
    throw new WorkInputError("INVALID", "Invalid queue bucket.");
  if (raw.sort !== undefined && !sorts.includes(raw.sort as QueueSort))
    throw new WorkInputError("INVALID", "Invalid queue sorting.");
  if (raw.severity !== undefined && !severities.includes(String(raw.severity)))
    throw new WorkInputError("INVALID", "Invalid severity.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    ...(raw.bucket === undefined ? {} : { bucket: raw.bucket as QueueBucket }),
    ...(raw.severity === undefined ? {} : {
      severity: raw.severity as "ERROR" | "WARNING" | "INFO",
    }),
    ...(raw.assignedTo === undefined ? {} : {
      assignedTo: parseWorkId(raw.assignedTo, "assignee ID"),
    }),
    sort: (raw.sort ?? "DEADLINE") as QueueSort,
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    warningHours: integer(raw.warningHours ?? 48, "warning threshold", 1, 8760),
    errorHours: integer(raw.errorHours ?? 12, "error threshold", 1, 8760),
    infoHours: integer(raw.infoHours ?? 120, "info threshold", 1, 8760),
    soonHours: integer(raw.soonHours ?? 6, "soon threshold", 1, 720),
  };
}
type TaskSnapshot = {
  id: string; captureId: string; externalTaskId: string;
  title: string; severity: string; disposition: string;
  required: boolean; ownerUserId: string | null;
  createdAt: Date; updatedAt: Date;
};
type LatestEscalation = {
  id: string; taskId: string; state: string;
  level: number; openedAt: Date;
};
type LatestCheck = {
  taskId: string; outcome: string; checkedAt: Date;
};
export function queueDeadline(task: TaskSnapshot, query: QueueQuery) {
  const hours = task.severity === "ERROR" ? query.errorHours :
    task.severity === "WARNING" ? query.warningHours : query.infoHours;
  return new Date(task.createdAt.getTime() + hours * 3600000);
}
export function classifyQueueTask(
  task: TaskSnapshot, query: QueueQuery, now: Date,
): { bucket: QueueBucket; dueAt: Date; overdueMinutes: number; urgency: number } {
  const dueAt = queueDeadline(task, query);
  const delta = now.getTime() - dueAt.getTime();
  const overdueMinutes = Math.max(0, Math.floor(delta / 60000));
  const severityWeight = task.severity === "ERROR" ? 300 :
    task.severity === "WARNING" ? 200 : 100;
  const urgency = severityWeight + Math.min(100000, overdueMinutes);
  if (task.disposition === "RESOLVED")
    return { bucket: "COMPLETED", dueAt, overdueMinutes: 0, urgency: 0 };
  if (task.disposition === "WAIVED")
    return { bucket: "WAIVED", dueAt, overdueMinutes: 0, urgency: 0 };
  if (delta >= 0)
    return { bucket: "OVERDUE", dueAt, overdueMinutes, urgency };
  if (delta >= -query.soonHours * 3600000)
    return { bucket: "DUE_SOON", dueAt, overdueMinutes: 0, urgency };
  if (!task.ownerUserId)
    return { bucket: "UNASSIGNED", dueAt, overdueMinutes: 0, urgency };
  if (task.disposition === "IN_REVIEW")
    return { bucket: "IN_PROGRESS", dueAt, overdueMinutes: 0, urgency };
  return { bucket: "AWAITING_REVIEW", dueAt, overdueMinutes: 0, urgency };
}
export function sortQueueRows(rows: QueueTask[], sort: QueueSort) {
  const severityRank: Record<string, number> = {
    ERROR: 0, WARNING: 1, INFO: 2,
  };
  return [...rows].sort((a, b) => {
    let difference = 0;
    if (sort === "OLDEST")
      difference = a.createdAt.localeCompare(b.createdAt);
    if (sort === "NEWEST")
      difference = b.createdAt.localeCompare(a.createdAt);
    if (sort === "SEVERITY")
      difference = (severityRank[a.severity] ?? 3) -
        (severityRank[b.severity] ?? 3);
    if (sort === "DEADLINE")
      difference = a.dueAt.localeCompare(b.dueAt);
    return difference || a.taskId.localeCompare(b.taskId);
  });
}

/**
 * Convert one queue bucket into a database predicate. The same UTC instant
 * and severity-specific policy are used by the SQL filter and UI classifier.
 * This avoids page-local bucket filtering, which could silently hide tasks.
 */
export function queueBucketPredicate(query: QueueQuery, now: Date):
  Record<string, unknown> {
  if (!query.bucket) return {};
  if (query.bucket === "COMPLETED")
    return { disposition: "RESOLVED" };
  if (query.bucket === "WAIVED")
    return { disposition: "WAIVED" };
  const active = { disposition: { notIn: ["RESOLVED", "WAIVED"] } };
  const due = (hours: number) =>
    new Date(now.getTime() - hours * 3600000);
  const soon = (hours: number) =>
    new Date(now.getTime() + query.soonHours * 3600000 -
      hours * 3600000);
  const severityWindows = [
    { severity: "ERROR", hours: query.errorHours },
    { severity: "WARNING", hours: query.warningHours },
    { severity: "INFO", hours: query.infoHours },
  ];
  if (query.bucket === "OVERDUE") {
    return {
      ...active,
      OR: severityWindows.map(item => ({
        severity: item.severity,
        createdAt: { lte: due(item.hours) },
      })),
    };
  }
  if (query.bucket === "DUE_SOON") {
    return {
      ...active,
      OR: severityWindows.map(item => ({
        severity: item.severity,
        createdAt: { gt: due(item.hours), lte: soon(item.hours) },
      })),
    };
  }
  const future = severityWindows.map(item => ({
    severity: item.severity,
    createdAt: { gt: soon(item.hours) },
  }));
  if (query.bucket === "UNASSIGNED")
    return { ...active, ownerUserId: null, OR: future };
  if (query.bucket === "IN_PROGRESS")
    return {
      ...active, ownerUserId: { not: null },
      disposition: "IN_REVIEW", OR: future,
    };
  return {
    ...active, ownerUserId: { not: null },
    disposition: { notIn: ["RESOLVED", "WAIVED", "IN_REVIEW"] },
    OR: future,
  };
}

/**
 * Choose a stable database order before pagination. Deadline sorting is
 * monotonic in (createdAt + threshold), so SQL can order by createdAt only
 * within a severity; for mixed severities we use a bounded exact strategy.
 */
export function queueDatabaseOrder(query: QueueQuery) {
  if (query.sort === "NEWEST")
    return [{ createdAt: "desc" as const }, { id: "desc" as const }];
  if (query.sort === "OLDEST")
    return [{ createdAt: "asc" as const }, { id: "asc" as const }];
  if (query.sort === "SEVERITY")
    return [{ severity: "asc" as const }, { createdAt: "asc" as const },
      { id: "asc" as const }];
  return [{ createdAt: "asc" as const }, { id: "asc" as const }];
}

function indexedCount(rows: Array<{ taskId: string; _count: { id: number } }>) {
  return new Map(rows.map(row => [row.taskId, row._count.id]));
}
export async function readIntegrityOperationsQueue(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Integrity operations queue denied.");
  const query = parseQueueQuery(value);
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
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.assignedTo ? { ownerUserId: query.assignedTo } : {}),
    ...queueBucketPredicate(query, now),
  };
  // Bounded database page. Bucket filtering is applied to this page only,
  // and the response explicitly exposes the scanned count.
  const [total, tasks] = await Promise.all([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, orderBy: queueDatabaseOrder(query),
      skip: query.offset, take: query.limit,
      select: {
        id: true, captureId: true, externalTaskId: true,
        title: true, severity: true, disposition: true,
        required: true, ownerUserId: true,
        createdAt: true, updatedAt: true,
      },
    }),
  ]);
  const ids = tasks.map(task => task.id);
  if (!ids.length)
    return {
      total, offset: query.offset, limit: query.limit,
      scanned: 0, matchedOnPage: 0,
      hasMore: query.offset < total,
      rows: [] as QueueTask[],
      bucketCountsOnPage: Object.fromEntries(buckets.map(x => [x, 0])),
      limitations: ["Bucket filters are evaluated before database pagination."],
    };
  const [
    escalations, notifications, unread, workLinks,
    assessments, providerChecks,
  ] = await Promise.all([
    db.integrityEscalation.findMany({
      where: { organizationId: scope.organizationId, taskId: { in: ids } },
      orderBy: [{ openedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, state: true,
        level: true, openedAt: true,
      },
    }),
    db.integrityNotification.groupBy({
      by: ["taskId"],
      where: { organizationId: scope.organizationId, taskId: { in: ids } },
      _count: { id: true },
    }),
    db.integrityNotification.groupBy({
      by: ["taskId"],
      where: {
        organizationId: scope.organizationId,
        taskId: { in: ids },
        recipientUserId: scope.userId,
        readAt: null, dismissedAt: null,
      },
      _count: { id: true },
    }),
    db.integrityReviewWorkLink.findMany({
      where: { organizationId: scope.organizationId, taskId: { in: ids } },
      select: { taskId: true, unlinkedAt: true },
    }),
    db.integrityEvidenceAssessment.groupBy({
      by: ["taskId"],
      where: { organizationId: scope.organizationId, taskId: { in: ids } },
      _count: { id: true },
    }),
    db.integrityProviderCheck.findMany({
      where: { organizationId: scope.organizationId, taskId: { in: ids } },
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      select: { taskId: true, outcome: true, checkedAt: true },
    }),
  ]);
  const latestEscalations = new Map<string, LatestEscalation>();
  for (const row of escalations)
    if (!latestEscalations.has(row.taskId))
      latestEscalations.set(row.taskId, row);
  const latestChecks = new Map<string, LatestCheck>();
  const checkCounts = new Map<string, number>();
  for (const row of providerChecks) {
    if (!latestChecks.has(row.taskId)) latestChecks.set(row.taskId, row);
    checkCounts.set(row.taskId, (checkCounts.get(row.taskId) ?? 0) + 1);
  }
  const workCounts = new Map<string, { linked: number; active: number }>();
  for (const link of workLinks) {
    const entry = workCounts.get(link.taskId) ?? { linked: 0, active: 0 };
    entry.linked++;
    if (!link.unlinkedAt) entry.active++;
    workCounts.set(link.taskId, entry);
  }
  const notificationCounts = indexedCount(notifications);
  const unreadCounts = indexedCount(unread);
  const assessmentCounts = indexedCount(assessments);
  const bucketCountsOnPage = Object.fromEntries(buckets.map(x => [x, 0])) as
    Record<QueueBucket, number>;
  const rows: QueueTask[] = tasks.map(task => {
    const classification = classifyQueueTask(task, query, now);
    bucketCountsOnPage[classification.bucket]++;
    const escalation = latestEscalations.get(task.id);
    const check = latestChecks.get(task.id);
    const work = workCounts.get(task.id) ?? { linked: 0, active: 0 };
    const flags: string[] = [];
    if (classification.bucket === "OVERDUE") flags.push("REVIEW_OVERDUE");
    if (!task.ownerUserId) flags.push("NO_ASSIGNEE");
    if (work.active === 0) flags.push("NO_ACTIVE_WORK_LINK");
    if (!check) flags.push("NO_PROVIDER_CHECK");
    else if (check.outcome !== "PASS")
      flags.push("PROVIDER_CHECK_NOT_PASSING");
    if (task.disposition === "RESOLVED" && (!check || check.outcome !== "PASS"))
      flags.push("HUMAN_RESOLVED_WITHOUT_PASSING_PROVIDER_CHECK");
    if (escalation && ["OPEN", "ACKNOWLEDGED"].includes(escalation.state))
      flags.push("ACTIVE_ESCALATION");
    return {
      taskId: task.id, captureId: task.captureId,
      externalTaskId: task.externalTaskId, title: task.title,
      severity: task.severity, disposition: task.disposition,
      required: task.required, ownerUserId: task.ownerUserId,
      createdAt: task.createdAt.toISOString(),
      updatedAt: task.updatedAt.toISOString(),
      dueAt: classification.dueAt.toISOString(),
      overdueMinutes: classification.overdueMinutes,
      bucket: classification.bucket, urgency: classification.urgency,
      escalation: escalation ? {
        id: escalation.id, state: escalation.state,
        level: escalation.level,
        openedAt: escalation.openedAt.toISOString(),
      } : null,
      notifications: {
        total: notificationCounts.get(task.id) ?? 0,
        unreadForCurrentUser: unreadCounts.get(task.id) ?? 0,
      },
      work, evidence: {
        assessments: assessmentCounts.get(task.id) ?? 0,
        providerChecks: checkCounts.get(task.id) ?? 0,
        latestProviderOutcome: check?.outcome ?? null,
        latestProviderCheckedAt: check?.checkedAt.toISOString() ?? null,
      },
      flags,
    };
  });
  const filtered = rows;
  return {
    total, offset: query.offset, limit: query.limit,
    scanned: tasks.length, matchedOnPage: filtered.length,
    hasMore: query.offset + tasks.length < total,
    rows: sortQueueRows(filtered, query.sort),
    bucketCountsOnPage,
    limitations: [
      "Queue status is operational and does not certify a security control.",
      "Provider check status is descriptive, not a current evidence validity gate.",
      "Bucket filtering is global within the selected organization and capture.",
      "Deadline and severity presentation sorting applies to this database page; use OLDEST or NEWEST for global chronological ordering.",
      "No automatic review or remediation transitions are performed.",
    ],
  };
}
export type QueueSnapshot = {
  captureId: string;
  generatedAt: string;
  rows: Array<{
    taskId: string; bucket: QueueBucket; urgency: number;
    severity: string; dueAt: string; flags: string[];
  }>;
  digest: string;
};
export function queueSnapshot(
  captureId: string, rows: QueueTask[], now: Date,
): QueueSnapshot {
  const canonical = rows.map(row => ({
    taskId: row.taskId, bucket: row.bucket,
    urgency: row.urgency, severity: row.severity,
    dueAt: row.dueAt, flags: [...row.flags].sort(),
  })).sort((a, b) => a.taskId.localeCompare(b.taskId));
  const digest = createHash("sha256")
    .update(JSON.stringify({ captureId, canonical })).digest("hex");
  return {
    captureId, generatedAt: now.toISOString(),
    rows: canonical, digest,
  };
}
