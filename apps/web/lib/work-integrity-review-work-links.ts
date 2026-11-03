import { db } from "@cyberpilot/database";
import { createHash } from "node:crypto";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Work associations provide explicit, auditable traceability. They do not
 * certify that work is complete, evidence is valid or remediation succeeded.
 */
export type ReviewWorkAction = "LINK" | "UNLINK" | "RELINK";
export type ReviewWorkCommand = {
  taskId: string;
  workItemId: string;
  action: ReviewWorkAction;
  expectedRevision: number;
  rationale: string;
};
export type ReviewWorkQuery = {
  taskId?: string;
  workItemId?: string;
  includeInactive: boolean;
  offset: number;
  limit: number;
};
const actions: ReviewWorkAction[] = ["LINK", "UNLINK", "RELINK"];
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected work association object.");
  return value as Record<string, unknown>;
}
function only(raw: Record<string, unknown>, keys: string[]) {
  const unknown = Object.keys(raw).find(key => !keys.includes(key));
  if (unknown)
    throw new WorkInputError("INVALID", "Unknown work association field: " + unknown);
}
function integer(value: unknown, name: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + name + ".");
  return value;
}
function reason(value: unknown) {
  if (typeof value !== "string" || value.trim().length < 12 ||
      value.length > 4000 || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid association rationale.");
  return value.trim();
}
export function parseReviewWorkCommand(value: unknown): ReviewWorkCommand {
  const raw = object(value);
  only(raw, ["taskId", "workItemId", "action", "expectedRevision", "rationale"]);
  if (!actions.includes(raw.action as ReviewWorkAction))
    throw new WorkInputError("INVALID", "Unknown work association action.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    workItemId: parseWorkId(raw.workItemId, "work item ID"),
    action: raw.action as ReviewWorkAction,
    expectedRevision: integer(raw.expectedRevision, "link revision", 0, 2147483646),
    rationale: reason(raw.rationale),
  };
}
export function parseReviewWorkQuery(value: unknown): ReviewWorkQuery {
  const raw = object(value);
  only(raw, ["taskId", "workItemId", "includeInactive", "offset", "limit"]);
  if (!raw.taskId && !raw.workItemId)
    throw new WorkInputError("INVALID", "Task or work item ID required.");
  if (raw.includeInactive !== undefined &&
      typeof raw.includeInactive !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeInactive flag.");
  return {
    ...(raw.taskId === undefined ? {} :
      { taskId: parseWorkId(raw.taskId, "review task ID") }),
    ...(raw.workItemId === undefined ? {} :
      { workItemId: parseWorkId(raw.workItemId, "work item ID") }),
    includeInactive: raw.includeInactive === true,
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
  };
}
function canRead(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Work associations are unavailable.");
}
function canWrite(scope: ReviewScope) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Only admins can change work associations.");
}
export function nextReviewWorkLinkState(
  action: ReviewWorkAction, current: {
    revision: number; unlinkedAt: Date | null;
  } | null, expectedRevision: number,
) {
  const revision = current?.revision ?? 0;
  if (revision !== expectedRevision)
    throw new WorkInputError("CONFLICT", "Work association revision changed.");
  if (action === "LINK") {
    if (current)
      throw new WorkInputError("CONFLICT", "Association already exists; use RELINK.");
    return { revision: 1, active: true };
  }
  if (!current)
    throw new WorkInputError("MISSING", "Association not found.");
  if (action === "UNLINK") {
    if (current.unlinkedAt)
      throw new WorkInputError("CONFLICT", "Association is already inactive.");
    return { revision: revision + 1, active: false };
  }
  if (!current.unlinkedAt)
    throw new WorkInputError("CONFLICT", "Association is already active.");
  return { revision: revision + 1, active: true };
}
function isConflict(error: unknown) {
  return typeof error === "object" && error !== null &&
    "code" in error && (error.code === "P2002" || error.code === "P2034");
}
function commandDigest(command: ReviewWorkCommand) {
  return createHash("sha256").update(JSON.stringify(command)).digest("hex");
}
export async function changeReviewWorkAssociation(
  scope: ReviewScope, value: unknown,
) {
  canWrite(scope);
  const command = parseReviewWorkCommand(value);
  try {
    return await db.$transaction(async tx => {
      const [task, work, current] = await Promise.all([
        tx.integrityReviewTask.findFirst({
          where: {
            id: command.taskId,
            organizationId: scope.organizationId,
          },
          select: {
            id: true, captureId: true, disposition: true,
            revision: true,
          },
        }),
        tx.remediationWorkItem.findFirst({
          where: {
            id: command.workItemId,
            organizationId: scope.organizationId,
          },
          select: {
            id: true, remediationId: true, findingId: true,
            status: true, revision: true,
          },
        }),
        tx.integrityReviewWorkLink.findFirst({
          where: {
            organizationId: scope.organizationId,
            taskId: command.taskId,
            workItemId: command.workItemId,
          },
        }),
      ]);
      if (!task)
        throw new WorkInputError("MISSING", "Review task not found.");
      if (!work)
        throw new WorkInputError("MISSING", "Remediation work item not found.");
      if (task.disposition === "WAIVED" || task.disposition === "RESOLVED")
        throw new WorkInputError("CONFLICT",
          "Reopen the review before changing work associations.");
      const transition = nextReviewWorkLinkState(
        command.action, current, command.expectedRevision);
      const now = new Date();
      const updated = command.action === "LINK" ?
        await tx.integrityReviewWorkLink.create({
          data: {
            organizationId: scope.organizationId,
            taskId: task.id,
            workItemId: work.id,
            rationale: command.rationale,
            linkedByUserId: scope.userId,
            linkedAt: now,
          },
        }) :
        await (async () => {
          const claimed = await tx.integrityReviewWorkLink.updateMany({
            where: {
              id: current!.id,
              organizationId: scope.organizationId,
              revision: command.expectedRevision,
              unlinkedAt: command.action === "UNLINK" ? null : { not: null },
            },
            data: {
              revision: { increment: 1 },
              ...(command.action === "UNLINK" ? {
                unlinkedAt: now, unlinkedByUserId: scope.userId,
                unlinkReason: command.rationale,
              } : {
                linkedAt: now, linkedByUserId: scope.userId,
                unlinkedAt: null, unlinkedByUserId: null,
                unlinkReason: null, rationale: command.rationale,
              }),
            },
          });
          if (claimed.count !== 1)
            throw new WorkInputError("CONFLICT", "Concurrent work association change.");
          return tx.integrityReviewWorkLink.findFirstOrThrow({
            where: { id: current!.id, organizationId: scope.organizationId },
          });
        })();
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER", actorUserId: scope.userId,
          action: "integrity.review.work." + command.action.toLowerCase(),
          resourceType: "IntegrityReviewWorkLink",
          resourceId: updated.id,
          metadata: {
            taskId: task.id, captureId: task.captureId,
            workItemId: work.id, remediationId: work.remediationId,
            findingId: work.findingId,
            beforeRevision: current?.revision ?? 0,
            afterRevision: updated.revision,
            action: command.action,
            rationale: command.rationale,
            commandDigest: commandDigest(command),
            active: transition.active,
          },
        },
      });
      return {
        link: updated,
        action: command.action,
        active: transition.active,
        work: {
          id: work.id, status: work.status,
          remediationId: work.remediationId,
          findingId: work.findingId,
        },
        limitations: [
          "The link is an explicit operational association, not verified causation.",
          "No remediation status, finding status or CyberScore was changed.",
        ],
      };
    }, { isolationLevel: "Serializable" });
  } catch (error) {
    if (isConflict(error))
      throw new WorkInputError("CONFLICT", "Concurrent association change.");
    throw error;
  }
}
export async function listReviewWorkAssociations(
  scope: ReviewScope, value: unknown,
) {
  canRead(scope);
  const query = parseReviewWorkQuery(value);
  if (query.taskId) {
    const task = await db.integrityReviewTask.findFirst({
      where: { id: query.taskId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!task)
      throw new WorkInputError("MISSING", "Review task not found.");
  }
  if (query.workItemId) {
    const work = await db.remediationWorkItem.findFirst({
      where: { id: query.workItemId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!work)
      throw new WorkInputError("MISSING", "Work item not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    ...(query.taskId ? { taskId: query.taskId } : {}),
    ...(query.workItemId ? { workItemId: query.workItemId } : {}),
    ...(!query.includeInactive ? { unlinkedAt: null } : {}),
  };
  const [total, links] = await db.$transaction([
    db.integrityReviewWorkLink.count({ where }),
    db.integrityReviewWorkLink.findMany({
      where,
      orderBy: [{ linkedAt: "desc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, organizationId: true,
        taskId: true, workItemId: true,
        rationale: true, revision: true,
        linkedByUserId: true, linkedAt: true,
        unlinkedAt: true, unlinkedByUserId: true,
        unlinkReason: true,
        task: {
          select: {
            captureId: true, title: true,
            disposition: true, required: true,
          },
        },
        workItem: {
          select: {
            title: true, status: true, revision: true,
            remediationId: true, findingId: true,
            remediation: { select: { status: true } },
            finding: { select: { status: true } },
          },
        },
      },
    }),
  ]);
  return {
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + links.length < total,
    links: links.map(link => ({
      ...link, active: link.unlinkedAt === null,
    })),
    limitations: [
      "Linked work does not prove the review's security finding is remediated.",
      "The work and review state machines remain independent.",
    ],
  };
}
export async function inspectReviewWorkAssociation(
  scope: ReviewScope, linkId: string,
) {
  canRead(scope);
  const id = parseWorkId(linkId, "work association ID");
  const link = await db.integrityReviewWorkLink.findFirst({
    where: { id, organizationId: scope.organizationId },
  });
  if (!link)
    throw new WorkInputError("MISSING", "Work association not found.");
  const audits = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceType: "IntegrityReviewWorkLink",
      resourceId: link.id,
      action: { in: [
        "integrity.review.work.link",
        "integrity.review.work.unlink",
        "integrity.review.work.relink",
      ] },
    },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    select: {
      id: true, actorUserId: true,
      action: true, metadata: true, createdAt: true,
    },
  });
  const revisions = audits.map(audit => {
    const metadata = audit.metadata;
    const data = metadata && typeof metadata === "object" &&
      !Array.isArray(metadata) ?
      metadata as Record<string, unknown> : {};
    return {
      auditId: audit.id,
      action: audit.action,
      actorUserId: audit.actorUserId,
      createdAt: audit.createdAt,
      beforeRevision: data.beforeRevision,
      afterRevision: data.afterRevision,
      taskId: data.taskId,
      workItemId: data.workItemId,
      commandDigest: data.commandDigest,
      rationale: data.rationale,
    };
  });
  const gaps: string[] = [];
  if (revisions.length !== link.revision)
    gaps.push("AUDIT_COUNT_MISMATCH");
  for (let i = 0; i < revisions.length; i++) {
    const row = revisions[i]!;
    if (row.beforeRevision !== i || row.afterRevision !== i + 1)
      gaps.push("REVISION_SEQUENCE_MISMATCH");
    if (row.taskId !== link.taskId || row.workItemId !== link.workItemId)
      gaps.push("AUDIT_SCOPE_MISMATCH");
    if (typeof row.commandDigest !== "string" ||
        !/^[a-f0-9]{64}$/.test(row.commandDigest))
      gaps.push("COMMAND_DIGEST_MISSING");
    const expected = i === 0 ? "integrity.review.work.link" :
      i % 2 === 1 ? "integrity.review.work.unlink" :
      "integrity.review.work.relink";
    if (row.action !== expected)
      gaps.push("ACTION_SEQUENCE_MISMATCH");
  }
  const last = revisions.at(-1);
  if (last && (last.action === "integrity.review.work.unlink") !==
      (link.unlinkedAt !== null))
    gaps.push("CURRENT_LINK_STATE_MISMATCH");
  return {
    link, revisions, gaps: [...new Set(gaps)],
    consistent: gaps.length === 0,
    limitations: [
      "The ledger checks database audit consistency, not cryptographic authenticity.",
      "A consistent association ledger does not prove remediation.",
    ],
  };
}
