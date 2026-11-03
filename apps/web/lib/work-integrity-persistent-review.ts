import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import {
  WorkInputError, canReadWork, canManageWork, parseWorkId,
} from "./remediation-work-input";

export type ReviewScope = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type ReviewAction =
  | "ACKNOWLEDGE" | "START_REVIEW" | "RESOLVE" | "WAIVE" | "REOPEN";
export type ReviewDisposition =
  | "OPEN" | "ACKNOWLEDGED" | "IN_REVIEW"
  | "RESOLVED" | "WAIVED" | "REOPENED";
export type ReviewCreateInput = {
  captureId: string;
  externalTaskId: string;
  title: string;
  severity: "ERROR" | "WARNING" | "INFO";
  required: boolean;
};
export type ReviewCommandInput = {
  taskId: string;
  action: ReviewAction;
  expectedRevision: number;
  idempotencyKey: string;
  reason: string | null;
  evidenceRefs: string[];
};
export type ReviewListQuery = {
  captureId?: string;
  disposition?: ReviewDisposition;
  required?: boolean;
  offset: number;
  limit: number;
};
export type ReviewEventQuery = {
  taskId: string;
  offset: number;
  limit: number;
};
const actions: ReviewAction[] = [
  "ACKNOWLEDGE", "START_REVIEW", "RESOLVE", "WAIVE", "REOPEN",
];
const dispositions: ReviewDisposition[] = [
  "OPEN", "ACKNOWLEDGED", "IN_REVIEW",
  "RESOLVED", "WAIVED", "REOPENED",
];
const severities = ["ERROR", "WARNING", "INFO"];
const states: Record<ReviewAction, readonly ReviewDisposition[]> = {
  ACKNOWLEDGE: ["OPEN", "REOPENED"],
  START_REVIEW: ["ACKNOWLEDGED"],
  RESOLVE: ["IN_REVIEW"],
  WAIVE: ["ACKNOWLEDGED", "IN_REVIEW"],
  REOPEN: ["RESOLVED", "WAIVED"],
};
const next: Record<ReviewAction, ReviewDisposition> = {
  ACKNOWLEDGE: "ACKNOWLEDGED",
  START_REVIEW: "IN_REVIEW",
  RESOLVE: "RESOLVED",
  WAIVE: "WAIVED",
  REOPEN: "REOPENED",
};
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected " + label + " object.");
  return value as Record<string, unknown>;
}
function only(raw: Record<string, unknown>, keys: readonly string[]) {
  const unknown = Object.keys(raw).find(x => !keys.includes(x));
  if (unknown)
    throw new WorkInputError("INVALID", "Unknown field: " + unknown);
}
function string(
  value: unknown, label: string, max: number, min = 1,
): string {
  if (typeof value !== "string" || value.trim().length < min ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value.trim();
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function scopeRead(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Review access denied.");
}
function scopeWrite(scope: ReviewScope) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Review changes require an administrator.");
}
function refs(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 100)
    throw new WorkInputError("INVALID", "Invalid evidence references.");
  const parsed = value.map(x => string(x, "evidence reference", 300));
  if (new Set(parsed).size !== parsed.length)
    throw new WorkInputError("INVALID", "Duplicate evidence reference.");
  return parsed;
}
export function parseReviewCreate(value: unknown): ReviewCreateInput {
  const raw = object(value, "review creation");
  only(raw, ["captureId", "externalTaskId", "title", "severity", "required"]);
  if (!severities.includes(raw.severity as string))
    throw new WorkInputError("INVALID", "Invalid review severity.");
  if (raw.required !== undefined && typeof raw.required !== "boolean")
    throw new WorkInputError("INVALID", "Invalid review requirement.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    externalTaskId: string(raw.externalTaskId, "external task ID", 200),
    title: string(raw.title, "review title", 240, 3),
    severity: raw.severity as ReviewCreateInput["severity"],
    required: raw.required !== false,
  };
}
export function parseReviewCommand(value: unknown): ReviewCommandInput {
  const raw = object(value, "review command");
  only(raw, [
    "taskId", "action", "expectedRevision",
    "idempotencyKey", "reason", "evidenceRefs",
  ]);
  if (!actions.includes(raw.action as ReviewAction))
    throw new WorkInputError("INVALID", "Invalid review action.");
  const action = raw.action as ReviewAction;
  const reason = raw.reason === undefined || raw.reason === null ?
    null : string(raw.reason, "review reason", 2000);
  const evidenceRefs = refs(raw.evidenceRefs ?? []);
  if (["RESOLVE", "WAIVE", "REOPEN"].includes(action) && !reason)
    throw new WorkInputError("INVALID", "A reason is required.");
  if (action === "RESOLVE" && !evidenceRefs.length)
    throw new WorkInputError("INVALID", "Resolution requires evidence.");
  if (action !== "RESOLVE" && evidenceRefs.length)
    throw new WorkInputError("INVALID", "Only resolution accepts evidence references.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    action,
    expectedRevision: integer(raw.expectedRevision,
      "expected revision", 1, 2147483646),
    idempotencyKey: string(raw.idempotencyKey,
      "idempotency key", 128, 12),
    reason, evidenceRefs,
  };
}
export function parseReviewListQuery(value: unknown): ReviewListQuery {
  const raw = object(value, "review list query");
  only(raw, ["captureId", "disposition", "required", "offset", "limit"]);
  if (raw.disposition !== undefined &&
      !dispositions.includes(raw.disposition as ReviewDisposition))
    throw new WorkInputError("INVALID", "Invalid disposition filter.");
  if (raw.required !== undefined && typeof raw.required !== "boolean")
    throw new WorkInputError("INVALID", "Invalid required filter.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    ...(raw.disposition === undefined ? {} : {
      disposition: raw.disposition as ReviewDisposition,
    }),
    ...(raw.required === undefined ? {} : {
      required: raw.required as boolean,
    }),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
  };
}
export function parseReviewEventQuery(value: unknown): ReviewEventQuery {
  const raw = object(value, "review event query");
  only(raw, ["taskId", "offset", "limit"]);
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "limit", 1, 200),
  };
}
export function planReviewTransition(
  current: ReviewDisposition,
  command: ReviewCommandInput,
  ownerUserId: string | null,
  actorUserId: string,
  severity: string,
) {
  if (!states[command.action].includes(current))
    throw new WorkInputError("CONFLICT", "Invalid review state transition.");
  if (command.action === "WAIVE" && severity === "ERROR")
    throw new WorkInputError("FORBIDDEN", "Error reviews cannot be waived.");
  if (command.action !== "ACKNOWLEDGE" &&
      ownerUserId !== actorUserId)
    throw new WorkInputError("FORBIDDEN", "Only the acknowledged owner can transition the review.");
  if (command.action === "ACKNOWLEDGE" &&
      ownerUserId !== null && ownerUserId !== actorUserId)
    throw new WorkInputError("CONFLICT", "Review is owned by another user.");
  return {
    disposition: next[command.action],
    ownerUserId: command.action === "ACKNOWLEDGE" ?
      actorUserId : ownerUserId,
    completedAt: command.action === "RESOLVE" ||
      command.action === "WAIVE" ? new Date() : null,
    resolutionReason: command.action === "RESOLVE" ||
      command.action === "WAIVE" ? command.reason : null,
    resolutionRefs: command.action === "RESOLVE" ?
      command.evidenceRefs : [],
  };
}
export function reviewCommandDigest(command: ReviewCommandInput): string {
  return createHash("sha256").update(JSON.stringify({
    taskId: command.taskId, action: command.action,
    expectedRevision: command.expectedRevision,
    reason: command.reason, evidenceRefs: command.evidenceRefs,
  })).digest("hex");
}
function isUnique(error: unknown) {
  return typeof error === "object" && error !== null &&
    "code" in error && error.code === "P2002";
}
function isRetryable(error: unknown) {
  return typeof error === "object" && error !== null &&
    "code" in error && typeof error.code === "string" &&
    ["P2034", "P2010"].includes(error.code);
}
async function findCommand(
  scope: ReviewScope, key: string,
  digest: string, taskId: string,
) {
  const existing = await db.integrityReviewCommand.findUnique({
    where: { organizationId_actorUserId_idempotencyKey: {
      organizationId: scope.organizationId,
      actorUserId: scope.userId, idempotencyKey: key,
    } },
  });
  if (!existing) return null;
  if (existing.payloadDigest !== digest ||
      existing.taskId !== taskId)
    throw new WorkInputError("CONFLICT",
      "Idempotency key was previously used with a different command.");
  return existing.response;
}
export async function createPersistentReview(
  scope: ReviewScope, input: unknown,
) {
  scopeWrite(scope);
  const value = parseReviewCreate(input);
  const capture = await db.integrityCaseCapture.findFirst({
    where: { id: value.captureId, organizationId: scope.organizationId },
    select: { id: true, complete: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  if (!capture.complete)
    throw new WorkInputError("CONFLICT",
      "Review registration requires a complete capture.");
  try {
    return await db.$transaction(async tx => {
      const created = await tx.integrityReviewTask.create({
        data: {
          organizationId: scope.organizationId,
          captureId: value.captureId,
          externalTaskId: value.externalTaskId,
          title: value.title, severity: value.severity,
          required: value.required,
        },
      });
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER", actorUserId: scope.userId,
          action: "integrity.review.created",
          resourceType: "IntegrityReviewTask",
          resourceId: created.id,
          metadata: {
            captureId: value.captureId,
            externalTaskId: value.externalTaskId,
            required: value.required,
          },
        },
      });
      return created;
    });
  } catch (error) {
    if (isUnique(error))
      throw new WorkInputError("CONFLICT",
        "A review task already exists for this capture and external ID.");
    throw error;
  }
}
export async function listPersistentReviews(
  scope: ReviewScope, input: unknown,
) {
  scopeRead(scope);
  const query = parseReviewListQuery(input);
  const where = {
    organizationId: scope.organizationId,
    ...(query.captureId === undefined ? {} : {
      captureId: query.captureId,
    }),
    ...(query.disposition === undefined ? {} : {
      disposition: query.disposition,
    }),
    ...(query.required === undefined ? {} : {
      required: query.required,
    }),
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, orderBy: [{ createdAt: "desc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, captureId: true, externalTaskId: true,
        title: true, severity: true, required: true,
        disposition: true, revision: true,
        ownerUserId: true, completedAt: true,
        createdAt: true, updatedAt: true,
      },
    }),
  ]);
  return {
    total, tasks, offset: query.offset, limit: query.limit,
    hasMore: query.offset + tasks.length < total,
  };
}
export async function getPersistentReview(
  scope: ReviewScope, taskId: string,
) {
  scopeRead(scope);
  const task = await db.integrityReviewTask.findFirst({
    where: { id: parseWorkId(taskId), organizationId: scope.organizationId },
    select: {
      id: true, captureId: true, externalTaskId: true,
      title: true, severity: true, required: true,
      disposition: true, revision: true, ownerUserId: true,
      resolutionReason: true, resolutionRefs: true,
      completedAt: true, createdAt: true, updatedAt: true,
    },
  });
  if (!task) throw new WorkInputError("MISSING", "Review task not found.");
  return task;
}
export async function listPersistentReviewEvents(
  scope: ReviewScope, input: unknown,
) {
  scopeRead(scope);
  const query = parseReviewEventQuery(input);
  await getPersistentReview(scope, query.taskId);
  const where = {
    organizationId: scope.organizationId, taskId: query.taskId,
  };
  const [total, events] = await db.$transaction([
    db.integrityReviewEvent.count({ where }),
    db.integrityReviewEvent.findMany({
      where, orderBy: [
        { revisionAfter: "asc" }, { id: "asc" },
      ], skip: query.offset, take: query.limit,
      select: {
        id: true, action: true, actorUserId: true,
        before: true, after: true,
        revisionBefore: true, revisionAfter: true,
        reason: true, evidenceRefs: true, occurredAt: true,
      },
    }),
  ]);
  return {
    total, events, offset: query.offset, limit: query.limit,
    hasMore: query.offset + events.length < total,
  };
}
export async function applyPersistentReviewCommand(
  scope: ReviewScope, input: unknown,
) {
  scopeWrite(scope);
  const command = parseReviewCommand(input);
  const digest = reviewCommandDigest(command);
  const existing = await findCommand(scope, command.idempotencyKey,
    digest, command.taskId);
  if (existing) return { replayed: true, result: existing };
  try {
    const response = await db.$transaction(async tx => {
      // A unique idempotency key is acquired inside the same transaction
      // as the state change, event and audit entry. A concurrent duplicate
      // cannot create a second event.
      const task = await tx.integrityReviewTask.findFirst({
        where: { id: command.taskId,
          organizationId: scope.organizationId },
      });
      if (!task)
        throw new WorkInputError("MISSING", "Review task not found.");
      if (task.revision !== command.expectedRevision)
        throw new WorkInputError("CONFLICT",
          "Review revision mismatch. Reload the task before retrying.");
      if (command.action === "RESOLVE") {
        // A submitted evidence ID must exist in the same organization.
        // Existence is not independent verification of its security state.
        const registered = await tx.securityEvidence.findMany({
          where: {
            organizationId: scope.organizationId,
            id: { in: command.evidenceRefs },
          },
          select: { id: true },
        });
        if (registered.length !== command.evidenceRefs.length)
          throw new WorkInputError("INVALID",
            "Resolution references must identify evidence in this organization.");
      }
      const planned = planReviewTransition(
        task.disposition, command, task.ownerUserId,
        scope.userId, task.severity);
      const result = await tx.integrityReviewTask.updateMany({
        where: {
          id: task.id, organizationId: scope.organizationId,
          revision: command.expectedRevision,
          disposition: task.disposition,
        },
        data: {
          disposition: planned.disposition,
          ownerUserId: planned.ownerUserId,
          completedAt: planned.completedAt,
          resolutionReason: planned.resolutionReason,
          resolutionRefs: planned.resolutionRefs,
          revision: { increment: 1 },
        },
      });
      if (result.count !== 1)
        throw new WorkInputError("CONFLICT",
          "Concurrent review update detected.");
      const event = await tx.integrityReviewEvent.create({
        data: {
          organizationId: scope.organizationId,
          taskId: task.id, actorUserId: scope.userId,
          action: command.action,
          before: task.disposition,
          after: planned.disposition,
          revisionBefore: task.revision,
          revisionAfter: task.revision + 1,
          reason: command.reason,
          evidenceRefs: command.evidenceRefs,
        },
      });
      const payload = {
        taskId: task.id, eventId: event.id,
        action: command.action, disposition: planned.disposition,
        revision: task.revision + 1,
        actorUserId: scope.userId,
        occurredAt: event.occurredAt.toISOString(),
      };
      await tx.integrityReviewCommand.create({
        data: {
          organizationId: scope.organizationId,
          taskId: task.id, actorUserId: scope.userId,
          idempotencyKey: command.idempotencyKey,
          payloadDigest: digest, response: payload,
        },
      });
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER", actorUserId: scope.userId,
          action: "integrity.review." + command.action.toLowerCase(),
          resourceType: "IntegrityReviewTask",
          resourceId: task.id,
          metadata: {
            eventId: event.id,
            revisionBefore: task.revision,
            revisionAfter: task.revision + 1,
            dispositionBefore: task.disposition,
            dispositionAfter: planned.disposition,
            evidenceRefCount: command.evidenceRefs.length,
          },
        },
      });
      return payload;
    }, { isolationLevel: "Serializable" });
    return { replayed: false, result: response };
  } catch (error) {
    if (isUnique(error) || isRetryable(error) ||
        (error instanceof WorkInputError && error.code === "CONFLICT")) {
      const duplicate = await findCommand(scope,
        command.idempotencyKey, digest, command.taskId);
      if (duplicate) return { replayed: true, result: duplicate };
      if (error instanceof WorkInputError) throw error;
      throw new WorkInputError("CONFLICT",
        "Concurrent review command. Reload and retry with a new key.");
    }
    throw error;
  }
}
