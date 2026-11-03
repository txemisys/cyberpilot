import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Human triage actions are deliberately separate from independent provider
 * verification and from the persistent review state machine.
 */
export type TriageAction =
  | "ASSIGN" | "UNASSIGN" | "SET_DUE_REMINDER"
  | "CLEAR_DUE_REMINDER" | "NOTIFY_OWNER" | "NOTIFY_ADMINS";
export type TriageCommand = {
  taskId: string;
  action: TriageAction;
  expectedRevision: number;
  recipientUserId?: string;
  note: string;
  idempotencyKey: string;
};
export type TriageBatch = {
  commands: TriageCommand[];
  stopOnError: boolean;
  dryRun: boolean;
};
export type TriageResult = {
  taskId: string;
  action: TriageAction;
  status: "APPLIED" | "REPLAYED" | "PREVIEW" | "FAILED";
  revisionBefore: number | null;
  revisionAfter: number | null;
  notificationIds: string[];
  errorCode: string | null;
  message: string;
};
const actions: TriageAction[] = [
  "ASSIGN", "UNASSIGN", "SET_DUE_REMINDER",
  "CLEAR_DUE_REMINDER", "NOTIFY_OWNER", "NOTIFY_ADMINS",
];
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected triage object.");
  return value as Record<string, unknown>;
}
function text(value: unknown, label: string, min: number, max: number) {
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
export function parseTriageCommand(value: unknown): TriageCommand {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "taskId", "action", "expectedRevision",
    "recipientUserId", "note", "idempotencyKey",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown triage field.");
  if (!actions.includes(raw.action as TriageAction))
    throw new WorkInputError("INVALID", "Invalid triage action.");
  const action = raw.action as TriageAction;
  if (action === "ASSIGN" && raw.recipientUserId === undefined)
    throw new WorkInputError("INVALID", "Assignment requires a recipient.");
  if (action !== "ASSIGN" && raw.recipientUserId !== undefined)
    throw new WorkInputError("INVALID", "Recipient not allowed for action.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    action,
    expectedRevision: integer(raw.expectedRevision, "revision", 1, 2147483646),
    ...(raw.recipientUserId === undefined ? {} : {
      recipientUserId: parseWorkId(raw.recipientUserId, "recipient user ID"),
    }),
    note: text(raw.note, "triage note", 12, 2000),
    idempotencyKey: text(raw.idempotencyKey, "idempotency key", 12, 180),
  };
}
export function parseTriageBatch(value: unknown): TriageBatch {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "commands", "stopOnError", "dryRun",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown batch field.");
  if (!Array.isArray(raw.commands) || !raw.commands.length ||
      raw.commands.length > 50)
    throw new WorkInputError("INVALID", "Batch must contain 1–50 commands.");
  if (raw.stopOnError !== undefined && typeof raw.stopOnError !== "boolean")
    throw new WorkInputError("INVALID", "Invalid stopOnError.");
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dryRun.");
  const commands = raw.commands.map(parseTriageCommand);
  const keys = commands.map(command => command.idempotencyKey);
  if (new Set(keys).size !== keys.length)
    throw new WorkInputError("INVALID", "Duplicate batch idempotency key.");
  return {
    commands, stopOnError: raw.stopOnError !== false,
    dryRun: raw.dryRun !== false,
  };
}
function isTerminal(disposition: string) {
  return disposition === "RESOLVED" || disposition === "WAIVED";
}
function notificationKind(action: TriageAction) {
  return action === "ASSIGN" ? "REVIEW_ASSIGNED" as const :
    "REVIEW_OVERDUE" as const;
}
export async function triageReviewBatch(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  const batch = parseTriageBatch(value);
  if (batch.dryRun ? !canReadWork(scope.role) : !canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Review triage denied.");
  const results: TriageResult[] = [];
  for (const command of batch.commands) {
    try {
      const result = await triageSingle(scope, command, batch.dryRun, now);
      results.push(result);
    } catch (error) {
      if (!(error instanceof WorkInputError)) throw error;
      results.push({
        taskId: command.taskId, action: command.action,
        status: "FAILED", revisionBefore: null, revisionAfter: null,
        notificationIds: [], errorCode: error.code,
        message: error.message,
      });
      if (batch.stopOnError) break;
    }
  }
  return {
    dryRun: batch.dryRun, requested: batch.commands.length,
    processed: results.length,
    applied: results.filter(x => x.status === "APPLIED").length,
    replayed: results.filter(x => x.status === "REPLAYED").length,
    previewed: results.filter(x => x.status === "PREVIEW").length,
    failed: results.filter(x => x.status === "FAILED").length,
    results,
    limitations: [
      "Triage is a human workflow operation, not provider verification.",
      "Batch commands commit individually and are not atomic as a group.",
      "Notifications are persisted in-app only.",
      "Reminder actions create or dismiss inbox messages; no timer is scheduled.",
    ],
  };
}
async function triageSingle(
  scope: ReviewScope, command: TriageCommand,
  dryRun: boolean, now: Date,
): Promise<TriageResult> {
  return db.$transaction(async tx => {
    const task = await tx.integrityReviewTask.findFirst({
      where: { id: command.taskId, organizationId: scope.organizationId },
      select: {
        id: true, title: true, severity: true,
        disposition: true, revision: true, ownerUserId: true,
      },
    });
    if (!task)
      throw new WorkInputError("MISSING", "Review task not found.");
    // Replays must be detected before checking a revision that the
    // original assignment may itself have advanced.
    const key = "triage:" + command.idempotencyKey;
    const previous = await tx.auditEvent.findFirst({
      where: {
        organizationId: scope.organizationId,
        action: "integrity.triage." + command.action.toLowerCase(),
        resourceType: "IntegrityReviewTask",
        resourceId: task.id,
        metadata: { path: ["idempotencyKey"], equals: key },
      },
      orderBy: { occurredAt: "desc" },
    });
    if (previous) {
      const metadata = previous.metadata as Record<string, unknown> | null;
      if (metadata?.note !== command.note ||
          metadata?.revisionBefore !== command.expectedRevision ||
          (command.action === "ASSIGN" &&
            metadata?.nextOwner !== command.recipientUserId))
        throw new WorkInputError("CONFLICT", "Triage idempotency key reused.");
      return {
        taskId: task.id, action: command.action,
        status: "REPLAYED" as const,
        revisionBefore: command.expectedRevision,
        revisionAfter: typeof metadata?.revisionAfter === "number" ?
          metadata.revisionAfter : task.revision,
        notificationIds: [],
        errorCode: null, message: "Existing triage command found.",
      };
    }
    if (task.revision !== command.expectedRevision)
      throw new WorkInputError("CONFLICT", "Review revision changed.");
    if (isTerminal(task.disposition))
      throw new WorkInputError("CONFLICT", "Cannot triage a closed review.");
    const admins = await tx.membership.findMany({
      where: {
        organizationId: scope.organizationId,
        role: { in: ["OWNER", "ADMIN"] },
      },
      select: { userId: true },
    });
    let recipients: string[] = [];
    if (command.action === "ASSIGN") {
      const member = await tx.membership.findFirst({
        where: {
          organizationId: scope.organizationId,
          userId: command.recipientUserId!,
        },
        select: { id: true },
      });
      if (!member)
        throw new WorkInputError("MISSING", "Assignee is not an organization member.");
      recipients = [command.recipientUserId!];
    }
    if (command.action === "NOTIFY_OWNER" || command.action === "SET_DUE_REMINDER") {
      if (!task.ownerUserId)
        throw new WorkInputError("CONFLICT", "Review has no assignee.");
      const owner = await tx.membership.findFirst({
        where: {
          organizationId: scope.organizationId,
          userId: task.ownerUserId,
        },
        select: { id: true },
      });
      if (!owner)
        throw new WorkInputError("CONFLICT", "Assignee is no longer a member.");
      recipients = [task.ownerUserId];
    }
    if (command.action === "NOTIFY_ADMINS")
      recipients = admins.map(member => member.userId);
    if (command.action === "UNASSIGN" && !task.ownerUserId)
      throw new WorkInputError("CONFLICT", "Review is already unassigned.");
    if (command.action === "CLEAR_DUE_REMINDER" && !task.ownerUserId)
      throw new WorkInputError("CONFLICT", "Review has no assignee.");
    if (dryRun) return {
      taskId: task.id, action: command.action,
      status: "PREVIEW" as const,
      revisionBefore: task.revision, revisionAfter: task.revision,
      notificationIds: [], errorCode: null,
      message: "Triage action validated; no writes performed.",
    };
    let revisionAfter = task.revision;
    if (command.action === "ASSIGN" || command.action === "UNASSIGN") {
      const changed = await tx.integrityReviewTask.updateMany({
        where: {
          id: task.id, organizationId: scope.organizationId,
          revision: task.revision,
          ownerUserId: task.ownerUserId,
        },
        data: {
          ownerUserId: command.action === "UNASSIGN" ?
            null : command.recipientUserId!,
        },
      });
      if (changed.count !== 1)
        throw new WorkInputError("CONFLICT", "Concurrent assignment change.");
      // Review revision is reserved for disposition events. Ownership
      // changes use a conditional owner CAS and a separate audit record.
    }
    const notificationIds: string[] = [];
    if (command.action === "CLEAR_DUE_REMINDER") {
      const reminders = await tx.integrityNotification.findMany({
        where: {
          organizationId: scope.organizationId,
          taskId: task.id,
          recipientUserId: task.ownerUserId!,
          kind: "REVIEW_OVERDUE",
          dismissedAt: null,
        },
        select: { id: true },
      });
      await tx.integrityNotification.updateMany({
        where: {
          organizationId: scope.organizationId,
          id: { in: reminders.map(item => item.id) },
        },
        data: { dismissedAt: now, revision: { increment: 1 } },
      });
      notificationIds.push(...reminders.map(item => item.id));
    }
    if (command.action === "ASSIGN" ||
        command.action === "SET_DUE_REMINDER" ||
        command.action === "NOTIFY_OWNER" ||
        command.action === "NOTIFY_ADMINS") {
      for (const recipientUserId of new Set(recipients)) {
        const dedupeKey = "triage:" + command.idempotencyKey;
        const existing = await tx.integrityNotification.findUnique({
          where: {
            organizationId_recipientUserId_dedupeKey: {
              organizationId: scope.organizationId,
              recipientUserId, dedupeKey,
            },
          },
        });
        if (existing) {
          notificationIds.push(existing.id);
          continue;
        }
        const notification = await tx.integrityNotification.create({
          data: {
            organizationId: scope.organizationId,
            taskId: task.id, recipientUserId,
            kind: notificationKind(command.action),
            dedupeKey,
            title: command.action === "ASSIGN" ?
              "Integrity review assigned" : "Integrity review requires attention",
            message: command.note,
            context: {
              action: command.action, taskId: task.id,
              revision: revisionAfter,
              severity: task.severity,
            },
          },
        });
        notificationIds.push(notification.id);
      }
    }
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "integrity.triage." + command.action.toLowerCase(),
        resourceType: "IntegrityReviewTask", resourceId: task.id,
        metadata: {
          idempotencyKey: key,
          revisionBefore: task.revision, revisionAfter,
          previousOwner: task.ownerUserId,
          nextOwner: command.action === "ASSIGN" ?
            command.recipientUserId! :
            command.action === "UNASSIGN" ? null : task.ownerUserId,
          recipientCount: recipients.length,
          notificationCount: notificationIds.length,
          note: command.note,
        },
      },
    });
    return {
      taskId: task.id, action: command.action,
      status: "APPLIED" as const,
      revisionBefore: task.revision, revisionAfter,
      notificationIds, errorCode: null,
      message: "Triage operation committed and audited.",
    };
  });
}
export async function inspectTriageHistory(
  scope: ReviewScope, value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Triage history denied.");
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "taskId", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown triage history filter.");
  const taskId = parseWorkId(raw.taskId, "review task ID");
  const offset = integer(raw.offset ?? 0, "offset", 0, 1000000);
  const limit = integer(raw.limit ?? 50, "limit", 1, 100);
  const task = await db.integrityReviewTask.findFirst({
    where: { id: taskId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const where = {
    organizationId: scope.organizationId,
    resourceType: "IntegrityReviewTask",
    resourceId: taskId,
    action: { startsWith: "integrity.triage." },
  };
  const [total, events] = await Promise.all([
    db.auditEvent.count({ where }),
    db.auditEvent.findMany({
      where, orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
      skip: offset, take: limit,
      select: {
        id: true, actorUserId: true, action: true,
        occurredAt: true, metadata: true,
      },
    }),
  ]);
  return {
    taskId, total, offset, limit,
    hasMore: offset + events.length < total,
    events,
  };
}
