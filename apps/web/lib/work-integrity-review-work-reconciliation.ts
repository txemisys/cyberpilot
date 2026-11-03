import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Consistency inspection of explicitly persisted review/work associations.
 * This is not a security re-scan and does not assert independent remediation.
 */
export type ReviewWorkConsistencyFinding = {
  code:
    | "MISSING_LINK_AUDIT" | "LINK_AUDIT_GAP"
    | "LINK_AUDIT_SCOPE_MISMATCH" | "LINK_AUDIT_STATE_MISMATCH"
    | "LINKED_WORK_MISSING" | "CROSS_TENANT_WORK"
    | "CROSS_TENANT_REVIEW" | "RESOLVED_REVIEW_ACTIVE_WORK"
    | "VERIFIED_REMEDIATION_OPEN_FINDING"
    | "WORK_DONE_WITHOUT_EVIDENCE"
    | "WORK_CANCELLED_ACTIVE_LINK";
  linkId: string;
  taskId: string;
  workItemId: string;
  detail: string;
};
export type ReviewWorkConsistencyInput = {
  captureId: string;
  offset: number;
  limit: number;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid consistency query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseReviewWorkConsistencyInput(
  value: unknown,
): ReviewWorkConsistencyInput {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown consistency parameter.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
  };
}
type LinkRow = {
  id: string; organizationId: string; taskId: string;
  workItemId: string; revision: number; unlinkedAt: Date | null;
  task: { organizationId: string; disposition: string };
  workItem: {
    organizationId: string; status: string;
    remediation: { status: string };
    finding: { status: string };
    evidenceLinks: Array<{ id: string }>;
  };
};
type AuditRow = {
  resourceId: string | null; action: string;
  actorUserId: string | null; metadata: unknown;
};
export function reconcileReviewWorkLink(
  link: LinkRow, audits: AuditRow[],
): ReviewWorkConsistencyFinding[] {
  const findings: ReviewWorkConsistencyFinding[] = [];
  const add = (
    code: ReviewWorkConsistencyFinding["code"], detail: string,
  ) => findings.push({
    code, linkId: link.id,
    taskId: link.taskId, workItemId: link.workItemId,
    detail,
  });
  if (link.task.organizationId !== link.organizationId)
    add("CROSS_TENANT_REVIEW", "Review belongs to another organization.");
  if (link.workItem.organizationId !== link.organizationId)
    add("CROSS_TENANT_WORK", "Work belongs to another organization.");
  if (!audits.length)
    add("MISSING_LINK_AUDIT", "No association audit events were found.");
  else if (audits.length !== link.revision)
    add("LINK_AUDIT_GAP", "Audit event count does not match association revision.");
  for (let index = 0; index < audits.length; index++) {
    const audit = audits[index]!;
    const data = audit.metadata && typeof audit.metadata === "object" &&
      !Array.isArray(audit.metadata) ?
      audit.metadata as Record<string, unknown> : {};
    if (audit.resourceId !== link.id ||
        data.taskId !== link.taskId ||
        data.workItemId !== link.workItemId)
      add("LINK_AUDIT_SCOPE_MISMATCH",
        "Association audit references a different task or work item.");
    if (data.beforeRevision !== index || data.afterRevision !== index + 1)
      add("LINK_AUDIT_GAP", "Association audit revision sequence is incomplete.");
    const expectedAction = index === 0 ? "integrity.review.work.link" :
      index % 2 === 1 ? "integrity.review.work.unlink" :
      "integrity.review.work.relink";
    if (audit.action !== expectedAction)
      add("LINK_AUDIT_STATE_MISMATCH", "Association action sequence is inconsistent.");
  }
  const last = audits.at(-1);
  if (last && (last.action === "integrity.review.work.unlink") !==
      (link.unlinkedAt !== null))
    add("LINK_AUDIT_STATE_MISMATCH",
      "The last audit action disagrees with the current association state.");
  if (link.unlinkedAt === null) {
    if (link.task.disposition === "RESOLVED")
      add("RESOLVED_REVIEW_ACTIVE_WORK",
        "Review was resolved while operational work remains associated.");
    if (link.workItem.status === "CANCELLED")
      add("WORK_CANCELLED_ACTIVE_LINK",
        "An active association references cancelled work.");
    if (link.workItem.status === "DONE" &&
        link.workItem.evidenceLinks.length === 0)
      add("WORK_DONE_WITHOUT_EVIDENCE",
        "Completed work has no active evidence links.");
    if (link.workItem.remediation.status === "VERIFIED" &&
        link.workItem.finding.status === "OPEN")
      add("VERIFIED_REMEDIATION_OPEN_FINDING",
        "Verified remediation status coexists with an open finding.");
  }
  return [...new Map(findings.map(finding =>
    [finding.code + ":" + finding.linkId, finding])).values()];
}
export async function inspectCaptureReviewWorkConsistency(
  scope: ReviewScope, value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Consistency inspection denied.");
  const query = parseReviewWorkConsistencyInput(value);
  const capture = await db.integrityCaseCapture.findFirst({
    where: {
      id: query.captureId,
      organizationId: scope.organizationId,
    },
    select: { id: true, complete: true, source: true, capturedAt: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    task: { captureId: capture.id },
  };
  const [total, links] = await db.$transaction([
    db.integrityReviewWorkLink.count({ where }),
    db.integrityReviewWorkLink.findMany({
      where,
      orderBy: [{ linkedAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, organizationId: true, taskId: true,
        workItemId: true, revision: true, unlinkedAt: true,
        task: { select: {
          organizationId: true, disposition: true,
        } },
        workItem: { select: {
          organizationId: true, status: true,
          remediation: { select: { status: true } },
          finding: { select: { status: true } },
          evidenceLinks: {
            where: { unlinkedAt: null },
            select: { id: true },
            take: 1,
          },
        } },
      },
    }),
  ]);
  const linkIds = links.map(link => link.id);
  const audits = linkIds.length ? await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceType: "IntegrityReviewWorkLink",
      resourceId: { in: linkIds },
      action: { in: [
        "integrity.review.work.link",
        "integrity.review.work.unlink",
        "integrity.review.work.relink",
      ] },
    },
    orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
    select: {
      resourceId: true, action: true,
      actorUserId: true, metadata: true,
    },
  }) : [];
  const byLink = new Map<string, typeof audits>();
  for (const audit of audits) {
    if (!audit.resourceId) continue;
    const bucket = byLink.get(audit.resourceId) ?? [];
    bucket.push(audit);
    byLink.set(audit.resourceId, bucket);
  }
  const inspected = links.map(link => {
    const findings = reconcileReviewWorkLink(
      link, byLink.get(link.id) ?? []);
    return {
      linkId: link.id, taskId: link.taskId,
      workItemId: link.workItemId,
      active: link.unlinkedAt === null,
      consistent: findings.length === 0,
      findings,
    };
  });
  const findings = inspected.flatMap(item => item.findings);
  const byCode: Record<string, number> = {};
  for (const finding of findings)
    byCode[finding.code] = (byCode[finding.code] ?? 0) + 1;
  return {
    capture, total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + links.length < total,
    inspected,
    summary: {
      linksInPage: inspected.length,
      consistentLinks: inspected.filter(x => x.consistent).length,
      inconsistentLinks: inspected.filter(x => !x.consistent).length,
      findings: findings.length,
      byCode,
    },
    limitations: [
      "Findings indicate data consistency or operational review needs, not confirmed vulnerabilities.",
      "The audit trail is database-local, not independently signed.",
      "The report does not change work, review, remediation or finding states.",
      "The summary covers only the requested page.",
    ],
  };
}
