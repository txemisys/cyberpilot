import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";
import { buildReviewEvidenceGate } from "./work-integrity-evidence-gates";

/**
 * Read-only operational lineage joins explicitly persisted review-to-work
 * associations with assessed evidence. Never infer a causal remediation.
 */
export type CaptureLineageQuery = {
  captureId: string;
  offset: number;
  limit: number;
  includeInactive: boolean;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid lineage query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseCaptureLineageQuery(value: unknown): CaptureLineageQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit", "includeInactive",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown lineage field.");
  if (raw.includeInactive !== undefined &&
      typeof raw.includeInactive !== "boolean")
    throw new WorkInputError("INVALID", "Invalid inactive filter.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    includeInactive: raw.includeInactive === true,
  };
}
export function summarizeCaptureLineage(rows: Array<{
  review: { disposition: string; required: boolean };
  evidence: { gate: string; acceptedCount: number; staleCount: number };
  work: Array<{ active: boolean; status: string; remediationStatus: string }>;
}>) {
  const summary = {
    tasks: rows.length,
    requiredTasks: 0,
    reviewOpen: 0,
    reviewResolved: 0,
    reviewWaived: 0,
    noEvidence: 0,
    humanAccepted: 0,
    evidenceActionRequired: 0,
    staleObservations: 0,
    noLinkedWork: 0,
    activeWorkLinks: 0,
    inactiveWorkLinks: 0,
    activeWorkTodo: 0,
    activeWorkInProgress: 0,
    activeWorkDone: 0,
    verifiedRemediations: 0,
  };
  for (const row of rows) {
    if (row.review.required) summary.requiredTasks++;
    if (row.review.disposition === "RESOLVED") summary.reviewResolved++;
    else if (row.review.disposition === "WAIVED") summary.reviewWaived++;
    else summary.reviewOpen++;
    if (row.evidence.gate === "NO_EVIDENCE") summary.noEvidence++;
    else if (row.evidence.gate === "HUMAN_ACCEPTED") summary.humanAccepted++;
    else summary.evidenceActionRequired++;
    summary.staleObservations += row.evidence.staleCount;
    const active = row.work.filter(work => work.active);
    if (!active.length) summary.noLinkedWork++;
    summary.activeWorkLinks += active.length;
    summary.inactiveWorkLinks += row.work.length - active.length;
    for (const work of active) {
      if (work.status === "TODO") summary.activeWorkTodo++;
      if (work.status === "IN_PROGRESS") summary.activeWorkInProgress++;
      if (work.status === "DONE") summary.activeWorkDone++;
      if (work.remediationStatus === "VERIFIED") summary.verifiedRemediations++;
    }
  }
  return summary;
}
export async function loadCaptureReviewLineage(
  scope: ReviewScope, value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Lineage access denied.");
  const query = parseCaptureLineageQuery(value);
  const capture = await db.integrityCaseCapture.findFirst({
    where: {
      id: query.captureId, organizationId: scope.organizationId,
    },
    select: {
      id: true, source: true, capturedAt: true,
      complete: true, caseCount: true, digest: true,
    },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    captureId: capture.id,
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, captureId: true, externalTaskId: true,
        title: true, severity: true, required: true,
        disposition: true, revision: true,
        assessmentRevision: true,
      },
    }),
  ]);
  const ids = tasks.map(task => task.id);
  const [assessments, workLinks] = await Promise.all([
    ids.length ? db.integrityEvidenceAssessment.findMany({
      where: {
        organizationId: scope.organizationId,
        taskId: { in: ids },
      },
      orderBy: [{ revision: "asc" }, { id: "asc" }],
      select: {
        id: true, taskId: true, evidenceId: true,
        decision: true, observationDigest: true,
        createdAt: true, assessorUserId: true,
        revision: true, source: true,
        controlId: true, observedAt: true,
      },
    }) : Promise.resolve([]),
    ids.length ? db.integrityReviewWorkLink.findMany({
      where: {
        organizationId: scope.organizationId,
        taskId: { in: ids },
        ...(!query.includeInactive ? { unlinkedAt: null } : {}),
      },
      orderBy: [{ linkedAt: "asc" }, { id: "asc" }],
      select: {
        id: true, taskId: true, workItemId: true,
        rationale: true, revision: true,
        linkedAt: true, unlinkedAt: true,
        workItem: {
          select: {
            title: true, status: true,
            revision: true, remediationId: true,
            findingId: true,
            remediation: {
              select: { status: true, verifiedAt: true },
            },
            finding: {
              select: { status: true, severity: true },
            },
          },
        },
      },
    }) : Promise.resolve([]),
  ]);
  const evidenceIds = [...new Set(assessments.map(row => row.evidenceId))];
  const evidence = evidenceIds.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: evidenceIds },
    },
    select: {
      id: true, organizationId: true, source: true,
      domain: true, controlId: true, scope: true,
      state: true, schemaVersion: true,
      observedAt: true, updatedAt: true, details: true,
    },
  }) : [];
  const evidenceById = new Map(evidence.map(row => [row.id, row]));
  const assessmentsByTask = new Map<string, typeof assessments>();
  for (const assessment of assessments) {
    const bucket = assessmentsByTask.get(assessment.taskId) ?? [];
    bucket.push(assessment);
    assessmentsByTask.set(assessment.taskId, bucket);
  }
  const linksByTask = new Map<string, typeof workLinks>();
  for (const link of workLinks) {
    const bucket = linksByTask.get(link.taskId) ?? [];
    bucket.push(link);
    linksByTask.set(link.taskId, bucket);
  }
  const rows = tasks.map(task => {
    const reviews = assessmentsByTask.get(task.id) ?? [];
    const relevantEvidence = reviews.map(row =>
      evidenceById.get(row.evidenceId)).filter(
      (row): row is NonNullable<typeof row> => row !== undefined);
    const evidenceGate = buildReviewEvidenceGate(
      task, reviews, relevantEvidence);
    const work = (linksByTask.get(task.id) ?? []).map(link => ({
      id: link.id,
      workItemId: link.workItemId,
      rationale: link.rationale,
      linkedAt: link.linkedAt,
      unlinkedAt: link.unlinkedAt,
      active: link.unlinkedAt === null,
      revision: link.revision,
      title: link.workItem.title,
      status: link.workItem.status,
      workRevision: link.workItem.revision,
      remediationId: link.workItem.remediationId,
      remediationStatus: link.workItem.remediation.status,
      remediationVerifiedAt: link.workItem.remediation.verifiedAt,
      findingId: link.workItem.findingId,
      findingStatus: link.workItem.finding.status,
      findingSeverity: link.workItem.finding.severity,
    }));
    return {
      review: task,
      evidence: evidenceGate,
      work,
      linkage: {
        activeWorkCount: work.filter(link => link.active).length,
        workItemIds: [...new Set(work.filter(link =>
          link.active).map(link => link.workItemId))],
        hasHumanAcceptedEvidence: evidenceGate.gate === "HUMAN_ACCEPTED",
        hasVerifiedRemediationRecord: work.some(link =>
          link.active && link.remediationStatus === "VERIFIED" &&
          link.remediationVerifiedAt !== null),
        independentlyVerified: false,
      },
    };
  });
  return {
    capture,
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + rows.length < total,
    rows,
    summary: summarizeCaptureLineage(rows),
    limitations: [
      "The lineage graph contains explicit stored associations only.",
      "A VERIFIED remediation status is a database status, not provider-backed independent verification.",
      "Human evidence acceptance is not proof of control security.",
      "Summary counts cover this page only.",
      "No review, finding, remediation or CyberScore is mutated by this report.",
    ],
  };
}
