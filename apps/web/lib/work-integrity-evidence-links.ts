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
    // PostgreSQL transaction-scoped advisory lock serializes withdrawals
    // of the same association, including concurrent requests.
    await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${original.id}, 0))`;
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
  }, { isolationLevel: "Serializable" });
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
export async function listIntegrityWorkLinkHistory(
  organizationId: string, captureId: string,
) {
  if (!organizationId) throw new WorkInputError("FORBIDDEN", "Organization required.");
  parseWorkId(captureId, "capture ID");
  const rows = await db.auditEvent.findMany({
    where: {
      organizationId,
      action: { in: [INTEGRITY_WORK_LINK_ACTION, INTEGRITY_WORK_UNLINK_ACTION] },
      resourceType: INTEGRITY_WORK_LINK_RESOURCE,
      metadata: { path: ["captureId"], equals: captureId },
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: AUDIT_LINK_HISTORY_LIMIT,
    select: {
      id: true, action: true, resourceId: true, actorUserId: true,
      occurredAt: true, metadata: true,
    },
  });
  const events: IntegrityLinkHistoryEvent[] = rows.flatMap(row => {
    const metadata = row.metadata;
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return [];
    const data = metadata as Record<string, unknown>;
    if (data.captureId !== captureId || typeof data.caseKey !== "string" ||
        !row.resourceId) return [];
    const isUnlink = row.action === INTEGRITY_WORK_UNLINK_ACTION;
    return [{
      auditId: row.id,
      originalAuditId: isUnlink && typeof data.originalAuditId === "string" ?
        data.originalAuditId : null,
      action: isUnlink ? "UNLINK" as const : "LINK" as const,
      captureId, caseKey: data.caseKey, workItemId: row.resourceId,
      actorUserId: row.actorUserId, occurredAt: row.occurredAt.toISOString(),
    }];
  });
  return { ...projectIntegrityLinkHistory(events), truncated: rows.length === AUDIT_LINK_HISTORY_LIMIT };
}
export async function listIntegrityWorkLinks(
  organizationId: string, captureId: string,
): Promise<IntegrityWorkLink[]> {
  const history = await listIntegrityWorkLinkHistory(organizationId, captureId);
  return history.active.map(event => ({
    auditId: event.auditId, captureId: event.captureId, caseKey: event.caseKey,
    workItemId: event.workItemId, actorUserId: event.actorUserId,
    occurredAt: event.occurredAt,
  }));
}
