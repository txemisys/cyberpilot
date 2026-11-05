import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { triageReviewBatch } from "./work-integrity-review-triage";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Operator-initiated, explicitly approved interventions. This is not
 * a scheduler. Every write delegates to the existing audited triage
 * transaction; remediation status and independent provider findings
 * are intentionally outside this contract.
 */
export type InterventionKind = "REMIND_OWNER" | "NOTIFY_ADMINS" |
  "ASSIGN_OWNER" | "UNASSIGN_OWNER" | "CLEAR_REMINDERS";
export type InterventionInput = {
  captureId: string;
  commands: InterventionCommand[];
  dryRun: boolean;
  stopOnError: boolean;
};
export type InterventionCommand = {
  taskId: string;
  kind: InterventionKind;
  expectedRevision: number;
  expectedOwnerUserId: string | null;
  assigneeUserId?: string;
  note: string;
  idempotencyKey: string;
};
export type InterventionCandidate = {
  taskId: string;
  captureId: string;
  kind: InterventionKind;
  ownerUserId: string | null;
  revision: number;
  severity: string;
  disposition: string;
  dueAt: string;
  eligible: boolean;
  reason: string;
  fingerprint: string;
};
export type InterventionResult = {
  taskId: string;
  kind: InterventionKind;
  status: "PREVIEW" | "APPLIED" | "REPLAYED" | "FAILED" | "SKIPPED";
  errorCode: string | null;
  reason: string;
  revision: number | null;
  notificationIds: string[];
};
export type InterventionResponse = {
  schema: "cyberpilot.integrity.interventions.v1";
  organizationId: string;
  captureId: string;
  dryRun: boolean;
  requested: number;
  processed: number;
  applied: number;
  replayed: number;
  previewed: number;
  failed: number;
  skipped: number;
  results: InterventionResult[];
  digest: string;
  warnings: string[];
};
const kinds: readonly InterventionKind[] = [
  "REMIND_OWNER", "NOTIFY_ADMINS", "ASSIGN_OWNER",
  "UNASSIGN_OWNER", "CLEAR_REMINDERS",
];
function object(value: unknown, what: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected " + what + " object.");
  return value as Record<string, unknown>;
}
function strictKeys(value: Record<string, unknown>, allowed: readonly string[]) {
  const bad = Object.keys(value).find(key => !allowed.includes(key));
  if (bad) throw new WorkInputError("INVALID", "Unknown intervention field: " + bad);
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function printable(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "string" || value.trim().length < min ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value.trim();
}
export function parseInterventionCommand(value: unknown): InterventionCommand {
  const raw = object(value, "intervention command");
  strictKeys(raw, [
    "taskId", "kind", "expectedRevision", "expectedOwnerUserId",
    "assigneeUserId", "note", "idempotencyKey",
  ]);
  if (!kinds.includes(raw.kind as InterventionKind))
    throw new WorkInputError("INVALID", "Unknown intervention kind.");
  const kind = raw.kind as InterventionKind;
  if (raw.expectedOwnerUserId === undefined)
    throw new WorkInputError("INVALID", "Expected owner must be explicit.");
  if (raw.expectedOwnerUserId !== null)
    parseWorkId(raw.expectedOwnerUserId, "expected owner user ID");
  if (kind === "ASSIGN_OWNER") {
    parseWorkId(raw.assigneeUserId, "assignee user ID");
  } else if (raw.assigneeUserId !== undefined) {
    throw new WorkInputError("INVALID", "Assignee is only valid for assignment.");
  }
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    kind,
    expectedRevision: integer(raw.expectedRevision, "review revision", 1, 2147483646),
    expectedOwnerUserId: raw.expectedOwnerUserId as string | null,
    ...(kind === "ASSIGN_OWNER" ? {
      assigneeUserId: raw.assigneeUserId as string,
    } : {}),
    note: printable(raw.note, "intervention note", 12, 2000),
    idempotencyKey: printable(raw.idempotencyKey, "idempotency key", 12, 180),
  };
}
export function parseInterventionInput(value: unknown): InterventionInput {
  const raw = object(value, "intervention batch");
  strictKeys(raw, ["captureId", "commands", "dryRun", "stopOnError"]);
  if (!Array.isArray(raw.commands) || !raw.commands.length ||
      raw.commands.length > 25)
    throw new WorkInputError("INVALID", "Interventions require 1–25 commands.");
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dryRun.");
  if (raw.stopOnError !== undefined && typeof raw.stopOnError !== "boolean")
    throw new WorkInputError("INVALID", "Invalid stopOnError.");
  const commands = raw.commands.map(parseInterventionCommand);
  const keys = commands.map(x => x.idempotencyKey);
  if (new Set(keys).size !== keys.length)
    throw new WorkInputError("INVALID", "Duplicate idempotency key.");
  const uniqueTasksAndActions = commands.map(x => x.taskId + ":" + x.kind);
  if (new Set(uniqueTasksAndActions).size !== uniqueTasksAndActions.length)
    throw new WorkInputError("INVALID", "Duplicate task/action in a batch.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    commands, dryRun: raw.dryRun !== false,
    stopOnError: raw.stopOnError !== false,
  };
}
export function interventionHash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export type InterventionTask = {
  id: string;
  captureId: string;
  severity: string;
  disposition: string;
  ownerUserId: string | null;
  revision: number;
  createdAt: Date;
};
export type InterventionMember = { userId: string; role: string };
export type InterventionContext = {
  task: InterventionTask;
  members: InterventionMember[];
  openReminders: number;
  now: Date;
};
export function evaluateIntervention(
  command: InterventionCommand, context: InterventionContext,
): InterventionCandidate {
  const { task, members, openReminders, now } = context;
  const dueHours = task.severity === "ERROR" ? 12 :
    task.severity === "WARNING" ? 48 : 120;
  const dueAt = new Date(task.createdAt.getTime() + dueHours * 3600000);
  const active = task.disposition !== "RESOLVED" &&
    task.disposition !== "WAIVED";
  const sameTask = task.id === command.taskId;
  const staleRevision = task.revision !== command.expectedRevision;
  const staleOwner = task.ownerUserId !== command.expectedOwnerUserId;
  const membership = new Set(members.map(x => x.userId));
  const adminCount = members.filter(x =>
    x.role === "OWNER" || x.role === "ADMIN").length;
  let reason = "Eligible for explicit operator confirmation.";
  if (!sameTask) reason = "Task identifier mismatch.";
  else if (!active) reason = "Closed reviews cannot be triaged.";
  else if (staleRevision) reason = "Review revision changed.";
  else if (staleOwner) reason = "Review owner changed.";
  else if (command.kind === "ASSIGN_OWNER" &&
           !membership.has(command.assigneeUserId!))
    reason = "Assignee is not a current organization member.";
  else if (command.kind === "ASSIGN_OWNER" &&
           task.ownerUserId === command.assigneeUserId)
    reason = "Review is already assigned to that member.";
  else if (command.kind === "UNASSIGN_OWNER" && !task.ownerUserId)
    reason = "Review is not assigned.";
  else if (["REMIND_OWNER", "CLEAR_REMINDERS"].includes(command.kind) &&
           !task.ownerUserId)
    reason = "Review has no owner.";
  else if (["REMIND_OWNER", "CLEAR_REMINDERS"].includes(command.kind) &&
           !membership.has(task.ownerUserId!))
    reason = "Review owner is no longer a current member.";
  else if (command.kind === "CLEAR_REMINDERS" && openReminders === 0)
    reason = "There are no active reminders to clear.";
  else if (command.kind === "NOTIFY_ADMINS" && adminCount === 0)
    reason = "No organization administrators can receive a notification.";
  const eligible = reason === "Eligible for explicit operator confirmation.";
  const canonical = {
    taskId: task.id, captureId: task.captureId, kind: command.kind,
    ownerUserId: task.ownerUserId, revision: task.revision,
    severity: task.severity, disposition: task.disposition,
    dueAt: dueAt.toISOString(), eligible, reason,
  };
  return { ...canonical, fingerprint: interventionHash(canonical) };
}
export function triageAction(kind: InterventionKind) {
  const map = {
    REMIND_OWNER: "SET_DUE_REMINDER",
    NOTIFY_ADMINS: "NOTIFY_ADMINS",
    ASSIGN_OWNER: "ASSIGN",
    UNASSIGN_OWNER: "UNASSIGN",
    CLEAR_REMINDERS: "CLEAR_DUE_REMINDER",
  } as const;
  return map[kind];
}
export function interventionResult(
  command: InterventionCommand,
  status: InterventionResult["status"],
  reason: string, errorCode: string | null,
  revision: number | null = null,
  notificationIds: string[] = [],
): InterventionResult {
  return {
    taskId: command.taskId, kind: command.kind, status,
    errorCode, reason, revision, notificationIds,
  };
}
export function interventionResponse(
  organizationId: string, input: InterventionInput,
  results: InterventionResult[],
): InterventionResponse {
  const canonical = {
    schema: "cyberpilot.integrity.interventions.v1" as const,
    organizationId, captureId: input.captureId,
    dryRun: input.dryRun, requested: input.commands.length,
    processed: results.length,
    applied: results.filter(x => x.status === "APPLIED").length,
    replayed: results.filter(x => x.status === "REPLAYED").length,
    previewed: results.filter(x => x.status === "PREVIEW").length,
    failed: results.filter(x => x.status === "FAILED").length,
    skipped: results.filter(x => x.status === "SKIPPED").length,
    results,
  };
  return {
    ...canonical, digest: interventionHash(canonical),
    warnings: [
      "Each command is independently transactional and audited, not globally atomic.",
      "Dry-run performs no writes and does not reserve a future execution.",
      "Notification delivery is inside the application, not an external channel.",
      "Review disposition, evidence validity and CyberScore are not changed.",
      "Concurrent review or ownership changes may reject a command.",
    ],
  };
}
export async function executeIntegrityInterventions(
  scope: ReviewScope, value: unknown, now = new Date(),
): Promise<InterventionResponse> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Interventions require administrator access.");
  const input = parseInterventionInput(value);
  const capture = await db.integrityCaseCapture.findFirst({
    where: { organizationId: scope.organizationId, id: input.captureId },
    select: { id: true },
  });
  if (!capture) throw new WorkInputError("MISSING", "Capture not found.");
  const results: InterventionResult[] = [];
  for (const command of input.commands) {
    try {
      const task = await db.integrityReviewTask.findFirst({
        where: {
          organizationId: scope.organizationId,
          captureId: input.captureId, id: command.taskId,
        },
        select: {
          id: true, captureId: true, severity: true, disposition: true,
          ownerUserId: true, revision: true, createdAt: true,
        },
      });
      if (!task) {
        results.push(interventionResult(command, "FAILED",
          "Task not found in the selected capture.", "MISSING"));
        if (input.stopOnError) break;
        continue;
      }
      const [members, reminders] = await Promise.all([
        db.membership.findMany({
          where: { organizationId: scope.organizationId },
          select: { userId: true, role: true },
        }),
        db.integrityNotification.count({
          where: {
            organizationId: scope.organizationId,
            taskId: task.id, kind: "REVIEW_OVERDUE",
            dismissedAt: null,
          },
        }),
      ]);
      const previous = await db.auditEvent.findFirst({
        where: {
          organizationId: scope.organizationId,
          resourceType: "IntegrityReviewTask",
          resourceId: command.taskId,
          action: "integrity.triage." + triageAction(command.kind).toLowerCase(),
          metadata: { path: ["idempotencyKey"],
            equals: "triage:" + command.idempotencyKey },
        },
        select: { id: true },
      });
      const eligibility = evaluateIntervention(command, {
        task, members, openReminders: reminders, now,
      });
      // Completed requests must reach the underlying command's replay
      // validation even after assignment changed the owner.
      if (!previous && !eligibility.eligible) {
        results.push(interventionResult(command, "FAILED",
          eligibility.reason, "CONFLICT", task.revision));
        if (input.stopOnError) break;
        continue;
      }
      const batch = await triageReviewBatch(scope, {
        dryRun: input.dryRun, stopOnError: true,
        commands: [{
          taskId: command.taskId, action: triageAction(command.kind),
          expectedRevision: command.expectedRevision,
          expectedOwnerUserId: command.expectedOwnerUserId,
          ...(command.assigneeUserId ? {
            recipientUserId: command.assigneeUserId,
          } : {}),
          note: command.note,
          idempotencyKey: command.idempotencyKey,
        }],
      }, now);
      const outcome = batch.results[0];
      if (!outcome) throw new WorkInputError("CONFLICT", "No triage result.");
      const state: InterventionResult["status"] =
        outcome.status === "PREVIEW" ? "PREVIEW" :
        outcome.status === "APPLIED" ? "APPLIED" :
        outcome.status === "REPLAYED" ? "REPLAYED" : "FAILED";
      results.push(interventionResult(command, state,
        outcome.message, outcome.errorCode,
        outcome.revisionAfter, outcome.notificationIds));
      if (state === "FAILED" && input.stopOnError) break;
    } catch (error) {
      if (!(error instanceof WorkInputError)) throw error;
      results.push(interventionResult(command, "FAILED", error.message, error.code));
      if (input.stopOnError) break;
    }
  }
  return interventionResponse(scope.organizationId, input, results);
}
