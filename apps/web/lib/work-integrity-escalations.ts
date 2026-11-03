import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";
import type { IntegrityEscalationState } from "@cyberpilot/database";

export type EscalationPolicy = {
  warningHours: number;
  errorHours: number;
  infoHours: number;
  repeatHours: number;
  maxLevel: number;
};
export type EscalationCommand = {
  escalationId: string;
  action: "ACKNOWLEDGE" | "RESOLVE" | "CANCEL" | "REOPEN";
  expectedRevision: number;
  reason: string;
};
export type EscalationQuery = {
  taskId?: string;
  state?: IntegrityEscalationState;
  offset: number;
  limit: number;
};
export type EscalationCandidate = {
  taskId: string;
  severity: string;
  disposition: string;
  ownerUserId: string | null;
  level: number;
  dueAt: Date;
  overdueMinutes: number;
  dedupeKey: string;
  reason: string;
};
const states: IntegrityEscalationState[] = [
  "OPEN", "ACKNOWLEDGED", "RESOLVED", "CANCELLED",
];
const defaultPolicy: EscalationPolicy = {
  warningHours: 48, errorHours: 12, infoHours: 120,
  repeatHours: 24, maxLevel: 3,
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected escalation object.");
  return value as Record<string, unknown>;
}
function only(raw: Record<string, unknown>, keys: string[]) {
  if (Object.keys(raw).some(key => !keys.includes(key)))
    throw new WorkInputError("INVALID", "Unknown escalation field.");
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function reason(value: unknown) {
  if (typeof value !== "string" || value.trim().length < 12 ||
      value.length > 2000 || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid escalation reason.");
  return value.trim();
}
export function parseEscalationPolicy(value: unknown): EscalationPolicy {
  if (value === undefined) return { ...defaultPolicy };
  const raw = object(value);
  only(raw, ["warningHours", "errorHours", "infoHours", "repeatHours", "maxLevel"]);
  return {
    warningHours: integer(raw.warningHours ?? defaultPolicy.warningHours,
      "warning threshold", 1, 8760),
    errorHours: integer(raw.errorHours ?? defaultPolicy.errorHours,
      "error threshold", 1, 8760),
    infoHours: integer(raw.infoHours ?? defaultPolicy.infoHours,
      "info threshold", 1, 8760),
    repeatHours: integer(raw.repeatHours ?? defaultPolicy.repeatHours,
      "repeat threshold", 1, 8760),
    maxLevel: integer(raw.maxLevel ?? defaultPolicy.maxLevel,
      "maximum level", 1, 5),
  };
}
export function parseEscalationCommand(value: unknown): EscalationCommand {
  const raw = object(value);
  only(raw, ["escalationId", "action", "expectedRevision", "reason"]);
  if (!["ACKNOWLEDGE", "RESOLVE", "CANCEL", "REOPEN"].includes(String(raw.action)))
    throw new WorkInputError("INVALID", "Unknown escalation action.");
  return {
    escalationId: parseWorkId(raw.escalationId, "escalation ID"),
    action: raw.action as EscalationCommand["action"],
    expectedRevision: integer(raw.expectedRevision, "revision", 1, 2147483646),
    reason: reason(raw.reason),
  };
}
export function parseEscalationQuery(value: unknown): EscalationQuery {
  const raw = object(value);
  only(raw, ["taskId", "state", "offset", "limit"]);
  if (raw.state !== undefined &&
      !states.includes(raw.state as IntegrityEscalationState))
    throw new WorkInputError("INVALID", "Invalid escalation state.");
  return {
    ...(raw.taskId === undefined ? {} : {
      taskId: parseWorkId(raw.taskId, "task ID"),
    }),
    ...(raw.state === undefined ? {} : {
      state: raw.state as IntegrityEscalationState,
    }),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
  };
}
type CandidateTask = {
  id: string; severity: string; disposition: string;
  ownerUserId: string | null; createdAt: Date;
};
export function calculateEscalationCandidate(
  task: CandidateTask,
  now: Date,
  policy: EscalationPolicy,
): EscalationCandidate | null {
  if (["RESOLVED", "WAIVED"].includes(task.disposition)) return null;
  const hours = task.severity === "ERROR" ? policy.errorHours :
    task.severity === "WARNING" ? policy.warningHours :
    policy.infoHours;
  const firstDue = task.createdAt.getTime() + hours * 3600000;
  if (firstDue > now.getTime()) return null;
  const elapsed = now.getTime() - firstDue;
  const level = Math.min(
    policy.maxLevel,
    1 + Math.floor(elapsed / (policy.repeatHours * 3600000)),
  );
  const dueAt = new Date(firstDue +
    (level - 1) * policy.repeatHours * 3600000);
  return {
    taskId: task.id, severity: task.severity,
    disposition: task.disposition, ownerUserId: task.ownerUserId,
    level, dueAt,
    overdueMinutes: Math.floor((now.getTime() - firstDue) / 60000),
    dedupeKey: "review-overdue:" + task.id + ":level:" + level,
    reason: "Review has exceeded the configured " +
      task.severity.toLowerCase() + " response window.",
  };
}
export function escalationNextState(
  current: IntegrityEscalationState,
  action: EscalationCommand["action"],
): IntegrityEscalationState {
  const allowed: Record<EscalationCommand["action"], IntegrityEscalationState[]> = {
    ACKNOWLEDGE: ["OPEN"],
    RESOLVE: ["OPEN", "ACKNOWLEDGED"],
    CANCEL: ["OPEN", "ACKNOWLEDGED"],
    REOPEN: ["RESOLVED", "CANCELLED"],
  };
  if (!allowed[action].includes(current))
    throw new WorkInputError("CONFLICT", "Escalation transition not allowed.");
  return {
    ACKNOWLEDGE: "ACKNOWLEDGED",
    RESOLVE: "RESOLVED",
    CANCEL: "CANCELLED",
    REOPEN: "OPEN",
  }[action] as IntegrityEscalationState;
}
export async function listEscalations(scope: ReviewScope, value: unknown) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Escalation access denied.");
  const query = parseEscalationQuery(value);
  const where = {
    organizationId: scope.organizationId,
    ...(query.taskId ? { taskId: query.taskId } : {}),
    ...(query.state ? { state: query.state } : {}),
  };
  const [total, escalations] = await db.$transaction([
    db.integrityEscalation.count({ where }),
    db.integrityEscalation.findMany({
      where, orderBy: [{ openedAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
    }),
  ]);
  return {
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + escalations.length < total,
    escalations,
  };
}
export async function previewEscalations(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Escalation preview denied.");
  const raw = object(value);
  only(raw, ["captureId", "policy", "offset", "limit"]);
  const captureId = parseWorkId(raw.captureId, "capture ID");
  const policy = parseEscalationPolicy(raw.policy);
  const offset = integer(raw.offset ?? 0, "offset", 0, 1000000);
  const limit = integer(raw.limit ?? 50, "limit", 1, 100);
  const capture = await db.integrityCaseCapture.findFirst({
    where: { id: captureId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    captureId,
    disposition: { notIn: ["RESOLVED", "WAIVED"] as
      Array<"RESOLVED" | "WAIVED"> },
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: offset, take: limit,
      select: {
        id: true, severity: true, disposition: true,
        ownerUserId: true, createdAt: true,
      },
    }),
  ]);
  const candidates = tasks.flatMap(task => {
    const candidate = calculateEscalationCandidate(task, now, policy);
    return candidate ? [candidate] : [];
  });
  return {
    captureId, total, offset, limit,
    hasMore: offset + tasks.length < total,
    candidates, policy,
    limitations: [
      "Preview does not persist escalations or deliver notifications.",
      "Thresholds are calculated from review task creation time.",
      "Only the selected page of review tasks is evaluated.",
    ],
  };
}
export async function openEscalation(
  scope: ReviewScope,
  value: unknown,
  now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Escalation creation denied.");
  const raw = object(value);
  only(raw, ["taskId", "policy"]);
  const taskId = parseWorkId(raw.taskId, "review task ID");
  const policy = parseEscalationPolicy(raw.policy);
  return db.$transaction(async tx => {
    const task = await tx.integrityReviewTask.findFirst({
      where: { id: taskId, organizationId: scope.organizationId },
      select: {
        id: true, severity: true, disposition: true,
        ownerUserId: true, createdAt: true,
      },
    });
    if (!task)
      throw new WorkInputError("MISSING", "Review task not found.");
    const candidate = calculateEscalationCandidate(task, now, policy);
    if (!candidate)
      throw new WorkInputError("CONFLICT", "Review is not overdue.");
    const existing = await tx.integrityEscalation.findUnique({
      where: {
        organizationId_taskId_dedupeKey: {
          organizationId: scope.organizationId,
          taskId, dedupeKey: candidate.dedupeKey,
        },
      },
    });
    if (existing) return { escalation: existing, replayed: true };
    const escalation = await tx.integrityEscalation.create({
      data: {
        organizationId: scope.organizationId, taskId,
        level: candidate.level, state: "OPEN",
        reason: candidate.reason,
        dedupeKey: candidate.dedupeKey,
        dueAt: candidate.dueAt,
        actorUserId: scope.userId,
      },
    });
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "integrity.escalation.opened",
        resourceType: "IntegrityEscalation",
        resourceId: escalation.id,
        metadata: {
          taskId, level: candidate.level, dueAt: candidate.dueAt.toISOString(),
          dedupeKey: candidate.dedupeKey,
        },
      },
    });
    return { escalation, replayed: false };
  });
}
export async function transitionEscalation(
  scope: ReviewScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Escalation transitions denied.");
  const command = parseEscalationCommand(value);
  return db.$transaction(async tx => {
    const current = await tx.integrityEscalation.findFirst({
      where: {
        id: command.escalationId,
        organizationId: scope.organizationId,
      },
    });
    if (!current)
      throw new WorkInputError("MISSING", "Escalation not found.");
    if (current.revision !== command.expectedRevision)
      throw new WorkInputError("CONFLICT", "Escalation revision changed.");
    const next = escalationNextState(current.state, command.action);
    const changed = await tx.integrityEscalation.updateMany({
      where: {
        id: current.id, organizationId: scope.organizationId,
        revision: current.revision,
      },
      data: {
        state: next, reason: command.reason,
        actorUserId: scope.userId,
        revision: { increment: 1 },
        ...(command.action === "ACKNOWLEDGE" ? { acknowledgedAt: now } : {}),
        ...(command.action === "RESOLVE" || command.action === "CANCEL" ?
          { resolvedAt: now } : {}),
        ...(command.action === "REOPEN" ?
          { resolvedAt: null, acknowledgedAt: null } : {}),
      },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT", "Concurrent escalation update.");
    const escalation = await tx.integrityEscalation.findUniqueOrThrow({
      where: { id: current.id },
    });
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "integrity.escalation." + command.action.toLowerCase(),
        resourceType: "IntegrityEscalation",
        resourceId: current.id,
        metadata: {
          taskId: current.taskId, before: current.state, after: next,
          revisionBefore: current.revision,
          revisionAfter: escalation.revision,
          reason: command.reason,
        },
      },
    });
    return { escalation };
  });
}
export async function summarizeEscalations(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Escalation summary denied.");
  const groups = await db.integrityEscalation.groupBy({
    by: ["state", "level"],
    where: { organizationId: scope.organizationId },
    _count: { id: true },
  });
  const statesCount: Record<IntegrityEscalationState, number> = {
    OPEN: 0, ACKNOWLEDGED: 0, RESOLVED: 0, CANCELLED: 0,
  };
  const levels: Record<number, number> = {};
  for (const group of groups) {
    statesCount[group.state] += group._count.id;
    levels[group.level] = (levels[group.level] ?? 0) + group._count.id;
  }
  return { states: statesCount, levels };
}
