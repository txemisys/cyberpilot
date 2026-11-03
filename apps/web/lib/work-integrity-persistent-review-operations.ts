import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { WorkInputError, canManageWork, canReadWork, parseWorkId } from "./remediation-work-input";
import {
  parseReviewCreate,
  type ReviewCreateInput,
  type ReviewScope,
} from "./work-integrity-persistent-review";

export type ReviewBatchCreateInput = {
  captureId: string;
  tasks: ReviewCreateInput[];
  rejectExisting: boolean;
};
export type ReviewDashboardQuery = {
  captureId?: string;
  includeOwners: boolean;
  maximumOwners: number;
  includeOverdue: boolean;
  overdueAfterHours: number;
};
export type ReviewDashboardOwner = {
  userId: string;
  total: number;
  outstanding: number;
  completed: number;
};
export type ReviewDashboardSeverity = {
  severity: string;
  total: number;
  open: number;
  acknowledged: number;
  inReview: number;
  resolved: number;
  waived: number;
  reopened: number;
};
export type ReviewDashboard = {
  captureId: string | null;
  evaluatedAt: string;
  totals: {
    tasks: number;
    required: number;
    outstanding: number;
    resolved: number;
    waived: number;
    unassigned: number;
    overdue: number;
    completedWithoutVerification: number;
  };
  bySeverity: ReviewDashboardSeverity[];
  owners: ReviewDashboardOwner[];
  oldestOutstanding: Array<{
    taskId: string;
    captureId: string;
    externalTaskId: string;
    disposition: string;
    severity: string;
    createdAt: string;
    ageHours: number;
  }>;
  limitations: string[];
};
function object(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
export function parseReviewBatchCreate(
  value: unknown,
): ReviewBatchCreateInput {
  const raw = object(value, "review batch creation");
  if (Object.keys(raw).some(x => ![
    "captureId", "tasks", "rejectExisting",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown review batch field.");
  const captureId = parseWorkId(raw.captureId, "capture ID");
  if (!Array.isArray(raw.tasks) || raw.tasks.length < 1 ||
      raw.tasks.length > 500)
    throw new WorkInputError("INVALID",
      "Batch must contain 1 to 500 review tasks.");
  if (raw.rejectExisting !== undefined &&
      typeof raw.rejectExisting !== "boolean")
    throw new WorkInputError("INVALID", "Invalid duplicate policy.");
  const tasks = raw.tasks.map(item => {
    const parsed = parseReviewCreate({
      ...object(item, "review batch task"),
      captureId,
    });
    return parsed;
  });
  if (new Set(tasks.map(x => x.externalTaskId)).size !== tasks.length)
    throw new WorkInputError("INVALID",
      "Batch contains duplicate external task IDs.");
  return {
    captureId, tasks, rejectExisting: raw.rejectExisting !== false,
  };
}
export function parseReviewDashboardQuery(
  value: unknown,
): ReviewDashboardQuery {
  const raw = object(value, "review dashboard query");
  if (Object.keys(raw).some(x => ![
    "captureId", "includeOwners", "maximumOwners",
    "includeOverdue", "overdueAfterHours",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown dashboard field.");
  for (const key of ["includeOwners", "includeOverdue"])
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid dashboard flag.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    includeOwners: raw.includeOwners !== false,
    maximumOwners: integer(raw.maximumOwners ?? 100,
      "maximum owners", 1, 500),
    includeOverdue: raw.includeOverdue !== false,
    overdueAfterHours: integer(raw.overdueAfterHours ?? 48,
      "overdue threshold", 1, 8760),
  };
}
function assertWrite(scope: ReviewScope) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only administrators can register review tasks.");
}
function assertRead(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Review access denied.");
}
export async function registerPersistentReviewBatch(
  scope: ReviewScope, value: unknown,
) {
  assertWrite(scope);
  const input = parseReviewBatchCreate(value);
  return db.$transaction(async tx => {
    const capture = await tx.integrityCaseCapture.findFirst({
      where: {
        id: input.captureId, organizationId: scope.organizationId,
      },
      select: { id: true, complete: true, caseCount: true },
    });
    if (!capture)
      throw new WorkInputError("MISSING", "Capture not found.");
    if (!capture.complete)
      throw new WorkInputError("CONFLICT",
        "Incomplete capture cannot seed authoritative review tasks.");
    const existing = await tx.integrityReviewTask.findMany({
      where: {
        organizationId: scope.organizationId,
        captureId: input.captureId,
        externalTaskId: { in: input.tasks.map(x => x.externalTaskId) },
      },
      select: { externalTaskId: true },
    });
    if (existing.length && input.rejectExisting)
      throw new WorkInputError("CONFLICT",
        "Review task IDs already registered for this capture.");
    const existingIds = new Set(existing.map(x => x.externalTaskId));
    const fresh = input.tasks.filter(x => !existingIds.has(x.externalTaskId));
    // createManyAndReturn provides the exact inserted IDs even when another
    // writer concurrently inserts an external ID. Audit each new task
    // atomically, not only the aggregate batch.
    const inserted = await tx.integrityReviewTask.createManyAndReturn({
      data: fresh.map(task => ({
        organizationId: scope.organizationId,
        captureId: input.captureId,
        externalTaskId: task.externalTaskId,
        title: task.title, severity: task.severity,
        required: task.required,
      })),
      skipDuplicates: !input.rejectExisting,
      select: {
        id: true, externalTaskId: true, required: true,
      },
    });
    if (inserted.length) {
      await tx.auditEvent.createMany({
        data: inserted.map(task => ({
          organizationId: scope.organizationId,
          actorType: "USER" as const,
          actorUserId: scope.userId,
          action: "integrity.review.created",
          resourceType: "IntegrityReviewTask",
          resourceId: task.id,
          metadata: {
            captureId: input.captureId,
            externalTaskId: task.externalTaskId,
            required: task.required,
            registration: "batch",
          },
        })),
      });
    }
    const created = { count: inserted.length };
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "integrity.review.batch_registered",
        resourceType: "IntegrityCaseCapture",
        resourceId: input.captureId,
        metadata: {
          submitted: input.tasks.length,
          created: created.count,
          skippedExisting: input.tasks.length - created.count,
          rejectExisting: input.rejectExisting,
        },
      },
    });
    return {
      captureId: input.captureId,
      submitted: input.tasks.length,
      created: created.count,
      skippedExisting: input.tasks.length - created.count,
      captureComplete: capture.complete,
      caseCount: capture.caseCount,
    };
  }, { isolationLevel: "Serializable" });
}
export function summarizeReviewDashboard(
  tasks: readonly {
    id: string;
    captureId: string;
    externalTaskId: string;
    severity: string;
    required: boolean;
    disposition: string;
    ownerUserId: string | null;
    createdAt: Date;
  }[],
  query: ReviewDashboardQuery,
  evaluatedAt: Date,
): ReviewDashboard {
  const now = evaluatedAt.getTime();
  if (!Number.isFinite(now))
    throw new WorkInputError("INVALID", "Invalid dashboard evaluation time.");
  const completed = new Set(["RESOLVED", "WAIVED"]);
  const outstanding = tasks.filter(x => !completed.has(x.disposition));
  const overdue = outstanding.filter(x =>
    query.includeOverdue &&
    (now - x.createdAt.getTime()) / 3600000 >
      query.overdueAfterHours);
  const severityNames = ["ERROR", "WARNING", "INFO"];
  const bySeverity: ReviewDashboardSeverity[] = severityNames.map(severity => {
    const relevant = tasks.filter(x => x.severity === severity);
    const count = (status: string) => relevant.filter(x =>
      x.disposition === status).length;
    return {
      severity, total: relevant.length,
      open: count("OPEN"),
      acknowledged: count("ACKNOWLEDGED"),
      inReview: count("IN_REVIEW"),
      resolved: count("RESOLVED"),
      waived: count("WAIVED"),
      reopened: count("REOPENED"),
    };
  });
  const byOwner = new Map<string, ReviewDashboardOwner>();
  if (query.includeOwners)
    for (const task of tasks) {
      if (task.ownerUserId === null) continue;
      const previous = byOwner.get(task.ownerUserId) ?? {
        userId: task.ownerUserId, total: 0,
        outstanding: 0, completed: 0,
      };
      previous.total++;
      if (completed.has(task.disposition)) previous.completed++;
      else previous.outstanding++;
      byOwner.set(task.ownerUserId, previous);
    }
  const owners = [...byOwner.values()].sort((a, b) =>
    b.outstanding - a.outstanding ||
    b.total - a.total ||
    a.userId.localeCompare(b.userId)).slice(0, query.maximumOwners);
  const oldestOutstanding = [...outstanding].sort((a, b) =>
    a.createdAt.getTime() - b.createdAt.getTime() ||
    a.id.localeCompare(b.id)).slice(0, 50).map(task => ({
    taskId: task.id, captureId: task.captureId,
    externalTaskId: task.externalTaskId,
    disposition: task.disposition, severity: task.severity,
    createdAt: task.createdAt.toISOString(),
    ageHours: Math.max(0, Math.round(
      (now - task.createdAt.getTime()) / 36000) / 100),
  }));
  return {
    captureId: query.captureId ?? null,
    evaluatedAt: evaluatedAt.toISOString(),
    totals: {
      tasks: tasks.length,
      required: tasks.filter(x => x.required).length,
      outstanding: outstanding.length,
      resolved: tasks.filter(x =>
        x.disposition === "RESOLVED").length,
      waived: tasks.filter(x =>
        x.disposition === "WAIVED").length,
      unassigned: outstanding.filter(x =>
        x.ownerUserId === null).length,
      overdue: overdue.length,
      completedWithoutVerification: tasks.filter(x =>
        completed.has(x.disposition)).length,
    },
    bySeverity, owners, oldestOutstanding,
    limitations: [
      "Completion is an administrative review disposition, not independent verification of remediation.",
      "Overdue thresholds are based on creation time, not a contractual SLA.",
      "The dashboard does not prove the integrity of external evidence.",
    ],
  };
}
export async function loadPersistentReviewDashboard(
  scope: ReviewScope, value: unknown,
) {
  assertRead(scope);
  const query = parseReviewDashboardQuery(value);
  const where: Prisma.IntegrityReviewTaskWhereInput = {
    organizationId: scope.organizationId,
    ...(query.captureId === undefined ? {} : {
      captureId: query.captureId,
    }),
  };
  const total = await db.integrityReviewTask.count({ where });
  if (total > 10000)
    throw new WorkInputError("INVALID",
      "Dashboard exceeds 10,000 tasks; filter by capture.");
  const tasks = await db.integrityReviewTask.findMany({
    where, take: 10000,
    select: {
      id: true, captureId: true, externalTaskId: true,
      severity: true, required: true,
      disposition: true, ownerUserId: true,
      createdAt: true,
    },
  });
  return summarizeReviewDashboard(tasks, query, new Date());
}
