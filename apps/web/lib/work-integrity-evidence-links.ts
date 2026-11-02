import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError, type WorkRole } from "./remediation-work-input";
import { readStoredIntegrityCapture } from "./work-integrity-persistent-captures";

export const INTEGRITY_WORK_LINK_ACTION = "INTEGRITY_CAPTURE_CASE_LINKED_TO_WORK";
export const INTEGRITY_WORK_LINK_RESOURCE = "REMEDIATION_WORK_ITEM";
export const INTEGRITY_WORK_UNLINK_ACTION = "INTEGRITY_CAPTURE_CASE_UNLINKED_FROM_WORK";
const AUDIT_LINK_HISTORY_LIMIT = 1000;
export type IntegrityWorkLinkScope = {
  organizationId: string; actorUserId: string; role: WorkRole;
};
export type IntegrityWorkLink = {
  auditId: string; captureId: string; caseKey: string; workItemId: string;
  actorUserId: string | null; occurredAt: string;
};

export function parseIntegrityWorkLinkInput(value: unknown): {
  captureId: string; caseKey: string; workItemId: string;
} {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected an evidence link object.");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some(key => !["captureId", "caseKey", "workItemId"].includes(key)))
    throw new WorkInputError("INVALID", "Unknown evidence link field.");
  const captureId = parseWorkId(input.captureId, "capture ID");
  const workItemId = parseWorkId(input.workItemId, "work item ID");
  if (typeof input.caseKey !== "string" || !input.caseKey ||
      input.caseKey.length > 1500 || /[\u0000-\u001f\u007f]/.test(input.caseKey))
    throw new WorkInputError("INVALID", "Invalid diagnostic case identity.");
  return { captureId, caseKey: input.caseKey, workItemId };
}
export async function linkIntegrityCaseToWork(
  scope: IntegrityWorkLinkScope, value: unknown,
): Promise<IntegrityWorkLink> {
  if (!scope.organizationId || !scope.actorUserId || !canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization administrator required.");
  const input = parseIntegrityWorkLinkInput(value);
  const capture = await readStoredIntegrityCapture(scope.organizationId, input.captureId);
  if (!capture) throw new WorkInputError("MISSING", "Capture not found.");
  const diagnostic = capture.cases.find(item => item.key === input.caseKey);
  if (!diagnostic) throw new WorkInputError("MISSING", "Diagnostic case not found.");
  const work = await db.remediationWorkItem.findFirst({
    where: { id: input.workItemId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!work) throw new WorkInputError("MISSING", "Work item not found in organization.");
  const audit = await db.auditEvent.create({
    data: {
      organizationId: scope.organizationId,
      actorType: "USER",
      actorUserId: scope.actorUserId,
      action: INTEGRITY_WORK_LINK_ACTION,
      resourceType: INTEGRITY_WORK_LINK_RESOURCE,
      resourceId: input.workItemId,
      metadata: {
        captureId: input.captureId, caseKey: diagnostic.key,
        source: capture.source, capturedAt: capture.capturedAt,
        diagnosticWorkItemId: diagnostic.workItemId,
        diagnosticCode: diagnostic.code, diagnosticResourceId: diagnostic.resourceId,
        workItemId: input.workItemId,
        limitation: "Historical diagnostic association; not security verification.",
      },
    },
    select: { id: true, occurredAt: true, actorUserId: true },
  });
  return {
    auditId: audit.id, captureId: input.captureId, caseKey: diagnostic.key,
    workItemId: input.workItemId, actorUserId: audit.actorUserId,
    occurredAt: audit.occurredAt.toISOString(),
  };
}
export function parseIntegrityWorkUnlinkInput(value: unknown): { auditId: string } {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected an unlink object.");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).length !== 1 || !("auditId" in input))
    throw new WorkInputError("INVALID", "Only auditId is accepted.");
  return { auditId: parseWorkId(input.auditId, "audit ID") };
}
export async function unlinkIntegrityCaseFromWork(
  scope: IntegrityWorkLinkScope, value: unknown,
): Promise<{ auditId: string; originalAuditId: string }> {
  if (!scope.organizationId || !scope.actorUserId || !canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization administrator required.");
  const { auditId } = parseIntegrityWorkUnlinkInput(value);
  return db.$transaction(async tx => {
    const original = await tx.auditEvent.findFirst({
      where: {
        id: auditId, organizationId: scope.organizationId,
        action: INTEGRITY_WORK_LINK_ACTION,
        resourceType: INTEGRITY_WORK_LINK_RESOURCE,
      },
      select: { id: true, resourceId: true, metadata: true },
    });
    if (!original) throw new WorkInputError("MISSING", "Evidence association not found.");
    const metadata = original.metadata;
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata))
      throw new WorkInputError("INVALID", "Invalid association metadata.");
    const data = metadata as Record<string, unknown>;
    if (typeof data.captureId !== "string" || typeof data.caseKey !== "string" ||
        !original.resourceId)
      throw new WorkInputError("INVALID", "Invalid association identity.");
    // A transaction-scoped advisory lock serializes withdrawals of this link.
    // ReadCommitted is required: a waiter must obtain a fresh statement snapshot
    // after the previous holder commits, otherwise Serializable can retain a
    // pre-lock snapshot and fail to see the withdrawal it must reject.
    await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${original.id}, 0))`;
    const prior = await tx.auditEvent.findFirst({
      where: {
        organizationId: scope.organizationId,
        action: INTEGRITY_WORK_UNLINK_ACTION,
        resourceType: INTEGRITY_WORK_LINK_RESOURCE,
        resourceId: original.resourceId,
        metadata: { path: ["originalAuditId"], equals: original.id },
      },
      select: { id: true },
    });
    if (prior) throw new WorkInputError("CONFLICT", "Evidence association already unlinked.");
    const audit = await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.actorUserId,
        action: INTEGRITY_WORK_UNLINK_ACTION,
        resourceType: INTEGRITY_WORK_LINK_RESOURCE,
        resourceId: original.resourceId,
        metadata: {
          originalAuditId: original.id, captureId: data.captureId,
          caseKey: data.caseKey, workItemId: original.resourceId,
          limitation: "Historical link withdrawn; audit history retained.",
        },
      },
      select: { id: true },
    });
    return { auditId: audit.id, originalAuditId: original.id };
  }, { isolationLevel: "ReadCommitted" });
}
export type IntegrityLinkHistoryEvent = {
  auditId: string; originalAuditId: string | null;
  action: "LINK" | "UNLINK"; captureId: string; caseKey: string;
  workItemId: string; actorUserId: string | null; occurredAt: string;
};
export function projectIntegrityLinkHistory(events: readonly IntegrityLinkHistoryEvent[]) {
  const withdrawn = new Set(events.filter(event => event.action === "UNLINK")
    .map(event => event.originalAuditId).filter((id): id is string => !!id));
  return {
    active: events.filter(event => event.action === "LINK" && !withdrawn.has(event.auditId)),
    withdrawn: events.filter(event => event.action === "LINK" && withdrawn.has(event.auditId)),
    events,
  };
}
export type IntegrityHistoryCursor = { occurredAt: string; auditId: string };
export type IntegrityHistoryPage = {
  events: IntegrityLinkHistoryEvent[];
  nextCursor: IntegrityHistoryCursor | null;
  hasMore: boolean;
};
type AuditHistoryRow = {
  id: string; action: string; resourceId: string | null;
  actorUserId: string | null; occurredAt: Date; metadata: unknown;
};
export function decodeIntegrityHistoryRow(
  row: AuditHistoryRow, captureId: string,
): IntegrityLinkHistoryEvent | null {
  const metadata = row.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return null;
  const data = metadata as Record<string, unknown>;
  if (data.captureId !== captureId || typeof data.caseKey !== "string" || !row.resourceId)
    return null;
  if (row.action !== INTEGRITY_WORK_LINK_ACTION &&
      row.action !== INTEGRITY_WORK_UNLINK_ACTION) return null;
  const isUnlink = row.action === INTEGRITY_WORK_UNLINK_ACTION;
  if (isUnlink && typeof data.originalAuditId !== "string") return null;
  return {
    auditId: row.id,
    originalAuditId: isUnlink ? data.originalAuditId as string : null,
    action: isUnlink ? "UNLINK" : "LINK",
    captureId, caseKey: data.caseKey, workItemId: row.resourceId,
    actorUserId: row.actorUserId, occurredAt: row.occurredAt.toISOString(),
  };
}
export function validateIntegrityHistoryCursor(value: IntegrityHistoryCursor) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      typeof value.occurredAt !== "string" ||
      !/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$/.test(value.occurredAt) ||
      !Number.isFinite(Date.parse(value.occurredAt)))
    throw new WorkInputError("INVALID", "Invalid history cursor timestamp.");
  return {
    occurredAt: new Date(value.occurredAt),
    auditId: parseWorkId(value.auditId, "audit ID"),
  };
}
type IntegrityHistoryReader = Pick<typeof db, "auditEvent">;
async function readIntegrityHistoryPage(
  reader: IntegrityHistoryReader,
  organizationId: string, captureId: string,
  cursor?: IntegrityHistoryCursor, pageSize = 100,
): Promise<IntegrityHistoryPage> {
  if (!organizationId) throw new WorkInputError("FORBIDDEN", "Organization required.");
  parseWorkId(captureId, "capture ID");
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > AUDIT_LINK_HISTORY_LIMIT)
    throw new WorkInputError("INVALID", "Invalid history page size.");
  const after = cursor ? validateIntegrityHistoryCursor(cursor) : null;
  const rows = await reader.auditEvent.findMany({
    where: {
      organizationId,
      action: { in: [INTEGRITY_WORK_LINK_ACTION, INTEGRITY_WORK_UNLINK_ACTION] },
      resourceType: INTEGRITY_WORK_LINK_RESOURCE,
      metadata: { path: ["captureId"], equals: captureId },
      ...(after ? { OR: [
        { occurredAt: { lt: after.occurredAt } },
        { occurredAt: after.occurredAt, id: { lt: after.auditId } },
      ] } : {}),
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: pageSize + 1,
    select: {
      id: true, action: true, resourceId: true, actorUserId: true,
      occurredAt: true, metadata: true,
    },
  });
  const hasMore = rows.length > pageSize;
  const visible = rows.slice(0, pageSize);
  const last = visible.at(-1);
  return {
    events: visible.flatMap(row => {
      const event = decodeIntegrityHistoryRow(row, captureId);
      return event ? [event] : [];
    }),
    hasMore,
    nextCursor: hasMore && last ?
      { occurredAt: last.occurredAt.toISOString(), auditId: last.id } : null,
  };
}
export async function listIntegrityWorkLinkHistoryPage(
  organizationId: string, captureId: string,
  cursor?: IntegrityHistoryCursor, pageSize = 100,
): Promise<IntegrityHistoryPage> {
  return readIntegrityHistoryPage(db, organizationId, captureId, cursor, pageSize);
}
export async function listIntegrityWorkLinkHistory(
  organizationId: string, captureId: string,
) {
  const page = await listIntegrityWorkLinkHistoryPage(
    organizationId, captureId, undefined, AUDIT_LINK_HISTORY_LIMIT,
  );
  return { ...projectIntegrityLinkHistory(page.events), truncated: page.hasMore };
}

/**
 * Reconstruct current state from every audit event, not just the visible history.
 * A withdrawal can be newer than the corresponding link by arbitrarily many pages.
 * A repeated cursor indicates a broken ordering contract and fails closed.
 */
export async function listCompleteIntegrityWorkLinkState(
  organizationId: string, captureId: string,
) {
  if (!organizationId) throw new WorkInputError("FORBIDDEN", "Organization required.");
  parseWorkId(captureId, "capture ID");
  return db.$transaction(async tx => {
    const events: IntegrityLinkHistoryEvent[] = [];
    let cursor: IntegrityHistoryCursor | undefined;
    const seen = new Set<string>();
    while (true) {
      const page = await readIntegrityHistoryPage(
        tx, organizationId, captureId, cursor, AUDIT_LINK_HISTORY_LIMIT,
      );
      events.push(...page.events);
      if (!page.hasMore) break;
      if (!page.nextCursor || seen.has(page.nextCursor.auditId))
        throw new WorkInputError("INVALID", "Integrity history pagination did not advance.");
      seen.add(page.nextCursor.auditId);
      cursor = page.nextCursor;
    }
    return projectIntegrityLinkHistory(events);
  }, { isolationLevel: "RepeatableRead" });
}
export async function listIntegrityWorkLinks(
  organizationId: string, captureId: string,
): Promise<IntegrityWorkLink[]> {
  const history = await listCompleteIntegrityWorkLinkState(organizationId, captureId);
  return history.active.map(event => ({
    auditId: event.auditId, captureId: event.captureId, caseKey: event.caseKey,
    workItemId: event.workItemId, actorUserId: event.actorUserId,
    occurredAt: event.occurredAt,
  }));
}
