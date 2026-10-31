import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import {
  canManageWork, parseAssignee, parseWorkDueAt, parseWorkId, parsePriority,
  parseRevision, parseStatus, transitionWorkStatus, WorkInputError,
  type WorkPriority, type WorkStatus,
} from "./remediation-work-input";
import type { WorkContext } from "./remediation-work-store";

/**
 * Controlled batch planning for remediation coordination.
 *
 * A batch changes only operational tracking data, never verification state,
 * evidence observations, finding resolution, remediation status or CyberScore.
 * Each request is bound to the caller's organization and a revision snapshot.
 */
export const MAX_WORK_BATCH = 50;
export type BatchField = "status" | "priority" | "assigneeUserId" | "dueAt";
export type BatchChange = {
  id: string;
  revision: number;
  field: BatchField;
  value: WorkStatus | WorkPriority | string | null | Date;
};
export type BatchRequest = {
  mode: "preview" | "apply";
  changes: BatchChange[];
  reason: string;
};
export type BatchItem = {
  id: string;
  revision: number;
  title: string;
  status: WorkStatus;
  priority: WorkPriority;
  assigneeUserId: string | null;
  dueAt: Date | null;
  completedAt: Date | null;
  organizationId: string;
};
export type BatchDecision = {
  id: string;
  field: BatchField;
  revision: number;
  current: string | null;
  proposed: string | null;
  outcome: "READY" | "UNCHANGED" | "STALE" | "MISSING" | "INVALID";
  message: string;
};
export type BatchPreview = {
  mode: "preview";
  ready: boolean;
  total: number;
  executable: number;
  decisions: BatchDecision[];
  note: string;
};
export type BatchApplied = {
  mode: "apply";
  changed: number;
  items: { id: string; revision: number }[];
  note: string;
};
type MinimalWork = Pick<BatchItem,
  "id" | "revision" | "title" | "status" | "priority" |
  "assigneeUserId" | "dueAt" | "completedAt"
>;

const fields = ["status", "priority", "assigneeUserId", "dueAt"] as const;
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Batch request must be a JSON object.");
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, allowed: readonly string[]) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key))
      throw new WorkInputError("INVALID", `Unexpected batch property: ${key}.`);
  }
}
function parseField(value: unknown): BatchField {
  if (typeof value !== "string" || !fields.some(field => field === value))
    throw new WorkInputError("INVALID", "Unsupported batch field.");
  return value as BatchField;
}
function parseValue(field: BatchField, value: unknown): BatchChange["value"] {
  if (field === "status") return parseStatus(value);
  if (field === "priority") return parsePriority(value);
  if (field === "assigneeUserId") {
    if (value === null || value === "") return null;
    return parseAssignee(value);
  }
  return parseWorkDueAt(value);
}
export function parseBatchRequest(value: unknown): BatchRequest {
  const data = record(value);
  exactKeys(data, ["mode", "changes", "reason"]);
  if (data.mode !== "preview" && data.mode !== "apply")
    throw new WorkInputError("INVALID", "Mode must be preview or apply.");
  if (!Array.isArray(data.changes) || !data.changes.length ||
      data.changes.length > MAX_WORK_BATCH)
    throw new WorkInputError("INVALID", `Provide 1–${MAX_WORK_BATCH} work changes.`);
  if (typeof data.reason !== "string")
    throw new WorkInputError("INVALID", "A reason is required.");
  const reason = data.reason.trim();
  if (reason.length < 10 || reason.length > 1000 ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(reason))
    throw new WorkInputError("INVALID", "Reason must contain 10–1000 printable characters.");
  const seen = new Set<string>();
  const changes: BatchChange[] = data.changes.map(raw => {
    const item = record(raw);
    exactKeys(item, ["id", "revision", "field", "value"]);
    const id = parseWorkId(item.id);
    const revision = parseRevision(item.revision);
    const field = parseField(item.field);
    const unique = `${id}:${field}`;
    if (seen.has(unique))
      throw new WorkInputError("INVALID", "Duplicate work item and field in batch.");
    seen.add(unique);
    return { id, revision, field, value: parseValue(field, item.value) };
  });
  // A single item may receive multiple field updates, but all must refer to
  // the same original revision; this prevents ambiguous execution order.
  const revisions = new Map<string, number>();
  for (const change of changes) {
    const previous = revisions.get(change.id);
    if (previous !== undefined && previous !== change.revision)
      throw new WorkInputError("INVALID", "Conflicting revisions for the same work item.");
    revisions.set(change.id, change.revision);
  }
  return { mode: data.mode, reason, changes };
}
function serialized(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}
function oldValue(item: MinimalWork, field: BatchField) {
  return item[field];
}
function effectiveValue(item: MinimalWork, change: BatchChange) {
  const candidate = change.value;
  if (change.field === "dueAt") return serialized(candidate);
  return serialized(candidate);
}
export function decideBatch(
  changes: readonly BatchChange[],
  items: readonly BatchItem[],
  members: ReadonlySet<string>,
): BatchDecision[] {
  const byId = new Map(items.map(item => [item.id, item]));
  return changes.map(change => {
    const item = byId.get(change.id);
    const base = {
      id: change.id, field: change.field, revision: change.revision,
      current: item ? serialized(oldValue(item, change.field)) : null,
      proposed: serialized(change.value),
    };
    if (!item)
      return { ...base, outcome: "MISSING" as const, message: "Work item is not accessible." };
    if (item.revision !== change.revision)
      return { ...base, outcome: "STALE" as const, message: "Work item revision changed." };
    if (change.field === "assigneeUserId" && change.value !== null &&
        !members.has(String(change.value)))
      return { ...base, outcome: "INVALID" as const, message: "Assignee is not in this organization." };
    if (change.field === "status") {
      try {
        transitionWorkStatus(item.status, change.value as WorkStatus);
      } catch (error) {
        return { ...base, outcome: "INVALID" as const,
          message: error instanceof Error ? error.message : "Invalid status transition." };
      }
    }
    if (serialized(oldValue(item, change.field)) === effectiveValue(item, change))
      return { ...base, outcome: "UNCHANGED" as const, message: "Value is already set." };
    return { ...base, outcome: "READY" as const, message: "Change can be applied." };
  });
}
function buildPatch(changes: readonly BatchChange[]) {
  const patch: {
    status?: WorkStatus;
    priority?: WorkPriority;
    assigneeUserId?: string | null;
    dueAt?: Date | null;
  } = {};
  for (const change of changes) {
    if (change.field === "status") patch.status = change.value as WorkStatus;
    else if (change.field === "priority") patch.priority = change.value as WorkPriority;
    else if (change.field === "assigneeUserId") patch.assigneeUserId = change.value as string | null;
    else patch.dueAt = change.value as Date | null;
  }
  return patch;
}
function auditSnapshot(item: MinimalWork) {
  return {
    title: item.title,
    revision: item.revision,
    status: item.status,
    priority: item.priority,
    assigneeUserId: item.assigneeUserId,
    dueAt: item.dueAt?.toISOString() ?? null,
    completedAt: item.completedAt?.toISOString() ?? null,
  };
}
function groupById(changes: readonly BatchChange[]) {
  const result = new Map<string, BatchChange[]>();
  for (const change of changes) {
    const current = result.get(change.id) ?? [];
    current.push(change);
    result.set(change.id, current);
  }
  return result;
}
async function gather(
  tx: Prisma.TransactionClient,
  organizationId: string,
  changes: readonly BatchChange[],
) {
  const ids = [...new Set(changes.map(change => change.id))];
  const items = await tx.remediationWorkItem.findMany({
    where: { organizationId, id: { in: ids } },
    select: {
      id: true, organizationId: true, title: true, revision: true,
      status: true, priority: true, assigneeUserId: true, dueAt: true, completedAt: true,
    },
  });
  const assigneeIds = [...new Set(changes.filter(
    change => change.field === "assigneeUserId" && change.value !== null,
  ).map(change => String(change.value)))];
  const memberships = assigneeIds.length ? await tx.membership.findMany({
    where: { organizationId, userId: { in: assigneeIds } },
    select: { userId: true },
  }) : [];
  return { items, members: new Set(memberships.map(member => member.userId)) };
}
function assertManager(context: WorkContext) {
  if (!canManageWork(context.role))
    throw new WorkInputError("FORBIDDEN", "Only owners and admins can apply batch changes.");
}
export async function previewWorkBatch(context: WorkContext, raw: unknown): Promise<BatchPreview> {
  assertManager(context);
  const request = parseBatchRequest(raw);
  if (request.mode !== "preview")
    throw new WorkInputError("INVALID", "Expected preview mode.");
  const data = await db.$transaction(async tx =>
    gather(tx, context.organizationId, request.changes));
  const decisions = decideBatch(request.changes, data.items, data.members);
  const executable = decisions.filter(result => result.outcome === "READY").length;
  return {
    mode: "preview", ready: decisions.every(result =>
      result.outcome === "READY" || result.outcome === "UNCHANGED"),
    total: decisions.length, executable, decisions,
    note: "Preview is advisory. Apply will recheck every revision atomically.",
  };
}
export async function applyWorkBatch(context: WorkContext, raw: unknown): Promise<BatchApplied> {
  assertManager(context);
  const request = parseBatchRequest(raw);
  if (request.mode !== "apply")
    throw new WorkInputError("INVALID", "Expected apply mode.");
  return db.$transaction(async tx => {
    const { items, members } = await gather(tx, context.organizationId, request.changes);
    const decisions = decideBatch(request.changes, items, members);
    const invalid = decisions.find(result =>
      result.outcome !== "READY" && result.outcome !== "UNCHANGED");
    if (invalid)
      throw new WorkInputError("CONFLICT",
        `Batch not applied: ${invalid.id} — ${invalid.message}`);
    const byId = new Map(items.map(item => [item.id, item]));
    const updated: BatchApplied["items"] = [];
    for (const [id, requested] of groupById(request.changes)) {
      const item = byId.get(id);
      if (!item) throw new WorkInputError("CONFLICT", "Work item disappeared.");
      const actual = requested.filter(change =>
        decisions.some(decision => decision.id === id &&
          decision.field === change.field && decision.outcome === "READY"));
      if (!actual.length) continue;
      const patch = buildPatch(actual);
      const nextStatus = patch.status ?? item.status;
      const now = new Date();
      const completedAt = nextStatus === "DONE"
        ? item.status === "DONE" ? item.completedAt ?? now : now
        : null;
      const result = await tx.remediationWorkItem.updateMany({
        where: { id, organizationId: context.organizationId, revision: item.revision },
        data: { ...patch, completedAt, revision: { increment: 1 } },
      });
      if (result.count !== 1)
        throw new WorkInputError("CONFLICT", "Concurrent modification; no batch changes committed.");
      const next = await tx.remediationWorkItem.findFirstOrThrow({
        where: { id, organizationId: context.organizationId },
      });
      await tx.remediationWorkEvent.create({
        data: {
          organizationId: context.organizationId,
          workItemId: id,
          actorUserId: context.userId,
          kind: item.status === "DONE" && nextStatus !== "DONE" ? "REOPENED" : "UPDATED",
          before: auditSnapshot(item),
          after: {
            ...auditSnapshot(next),
            batch: {
              fields: actual.map(change => change.field),
              reason: request.reason,
              operation: "BATCH_COORDINATION",
            },
          },
          comment: request.reason,
        },
      });
      updated.push({ id, revision: next.revision });
    }
    return {
      mode: "apply" as const, changed: updated.length, items: updated,
      note: "Only work coordination changed. Findings and verification remain unchanged.",
    };
  }, { isolationLevel: "Serializable", timeout: 20000 });
}
