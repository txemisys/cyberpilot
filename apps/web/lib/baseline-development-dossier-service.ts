import { db } from "@cyberpilot/database";
import {
  canonicalV2, sha256V2, verifyBaselineReportV2,
  type BaselineReportV2,
} from "@cyberpilot/risk-engine";
import {
  buildBaselineDevelopmentDossier,
  verifyBaselineDevelopmentDossier,
  type BaselineDossierInput,
  type BaselineDossierReport,
} from "./baseline-development-dossier";

export type BaselineDossierActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export class BaselineDossierAccessError extends Error {
  constructor(message: string) { super(message); }
}
const CAPS = {
  drafts: 1,
  revisions: 200,
  reviews: 200,
  reviewEvents: 500,
  actions: 200,
  actionEvents: 500,
} as const;
function date(value: Date | null): string | null {
  return value?.toISOString() ?? null;
}
function requireId(value: string, name: string) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value))
    throw new BaselineDossierAccessError("Invalid " + name);
}
function verifyStoredReport(raw: unknown,
  digest: string | null): boolean {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) ||
      typeof digest !== "string" ||
      !/^[a-f0-9]{64}$/.test(digest))
    return false;
  try {
    const candidate = raw as BaselineReportV2;
    return candidate.digest === digest &&
      verifyBaselineReportV2(candidate).valid;
  } catch { return false; }
}
export async function collectBaselineDevelopmentDossier(
  actor: BaselineDossierActor,
  generatedAt = new Date().toISOString(),
): Promise<BaselineDossierReport> {
  requireId(actor.organizationId, "organization");
  requireId(actor.userId, "user");
  if (!["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    throw new BaselineDossierAccessError(
      "Only organization reviewers can view the full development dossier.",
    );
  const membership = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId,
      userId: actor.userId,
      role: actor.role,
    },
    select: { role: true },
  });
  if (!membership)
    throw new BaselineDossierAccessError(
      "Active organization reviewer membership required.",
    );
  const organizationId = actor.organizationId;
  // All data comes from a single tenant scope. No query scans tenants,
  // mutates records, invokes providers or marks a review as accepted.
  const [drafts, revisions, reviews, reviewEvents,
    actions, actionEvents] = await Promise.all([
    db.baselineDraft.findMany({
      where: { organizationId, questionnaireVersion: 1 },
      take: CAPS.drafts + 1, orderBy: { updatedAt: "desc" },
    }),
    db.baselineRevision.findMany({
      where: { organizationId, questionnaireVersion: 1 },
      take: CAPS.revisions + 1,
      orderBy: { revision: "asc" },
    }),
    db.baselineReview.findMany({
      where: { organizationId, questionnaireVersion: 1 },
      take: CAPS.reviews + 1,
      orderBy: { sourceRevision: "asc" },
    }),
    db.baselineReviewEvent.findMany({
      where: { organizationId },
      take: CAPS.reviewEvents + 1,
      orderBy: { createdAt: "asc" },
    }),
    db.baselineFollowUp.findMany({
      where: { organizationId, questionnaireVersion: 1 },
      take: CAPS.actions + 1,
      orderBy: { questionId: "asc" },
    }),
    db.baselineFollowUpEvent.findMany({
      where: { organizationId },
      take: CAPS.actionEvents + 1,
      orderBy: { createdAt: "asc" },
    }),
  ]);
  const counts = {
    drafts: drafts.length,
    revisions: revisions.length,
    reviews: reviews.length,
    reviewEvents: reviewEvents.length,
    actions: actions.length,
    actionEvents: actionEvents.length,
  };
  const draft = drafts[0];
  const source: BaselineDossierInput = {
    organizationId, generatedAt,
    queryCaps: CAPS, sourceCounts: counts,
    draft: draft ? {
      id: draft.id,
      organizationId: draft.organizationId,
      revision: draft.revision,
      status: draft.status,
      responsesDigest: draft.responsesDigest,
      submittedAt: date(draft.submittedAt),
      updatedAt: draft.updatedAt.toISOString(),
    } : null,
    revisions: revisions.slice(0, CAPS.revisions).map(row => ({
      id: row.id,
      organizationId: row.organizationId,
      draftId: row.draftId,
      revision: row.revision,
      eventKind: row.eventKind,
      responsesDigest: row.responsesDigest,
      reportDigest: row.reportDigest,
      storedReportValid: row.report !== null &&
        verifyStoredReport(row.report, row.reportDigest),
      reportOrganizationId: (
        row.report && typeof row.report === "object" &&
        !Array.isArray(row.report) &&
        typeof (row.report as { organizationId?: unknown })
          .organizationId === "string"
      ) ? (row.report as { organizationId: string }).organizationId : null,
      actorUserId: row.actorUserId,
      createdAt: row.createdAt.toISOString(),
    })),
    reviews: reviews.slice(0, CAPS.reviews).map(row => ({
      id: row.id,
      organizationId: row.organizationId,
      draftId: row.draftId,
      sourceRevision: row.sourceRevision,
      reportDigest: row.reportDigest,
      revision: row.revision,
      state: row.state, scope: row.scope,
      issueCount: row.issueCount,
      blockingIssueCount: row.blockingIssueCount,
      findingsDigest: sha256V2(canonicalV2(row.reviewNotes)),
      reviewerUserId: row.reviewerUserId,
      completedAt: date(row.completedAt),
      updatedAt: row.updatedAt.toISOString(),
    })),
    reviewEvents: reviewEvents.slice(0, CAPS.reviewEvents).map(row => ({
      id: row.id,
      organizationId: row.organizationId,
      reviewId: row.reviewId,
      revision: row.revision,
      action: row.action,
      previousState: row.previousState,
      newState: row.newState,
      findingsDigest: row.findingsDigest,
      actorUserId: row.actorUserId,
      createdAt: row.createdAt.toISOString(),
    })),
    actions: actions.slice(0, CAPS.actions).map(row => ({
      id: row.id,
      organizationId: row.organizationId,
      questionId: row.questionId,
      sourceDraftRevision: row.sourceDraftRevision,
      revision: row.revision,
      status: row.status,
      ownerUserId: row.ownerUserId,
      evidenceReference: row.evidenceReference,
      dueAt: date(row.dueAt),
      completedAt: date(row.completedAt),
      updatedAt: row.updatedAt.toISOString(),
    })),
    actionEvents: actionEvents.slice(0, CAPS.actionEvents).map(row => ({
      id: row.id,
      organizationId: row.organizationId,
      followUpId: row.followUpId,
      revision: row.revision,
      action: row.action,
      previousStatus: row.previousStatus,
      nextStatus: row.nextStatus,
      actorUserId: row.actorUserId,
      createdAt: row.createdAt.toISOString(),
    })),
  };
  const report = buildBaselineDevelopmentDossier(source);
  if (!verifyBaselineDevelopmentDossier(report, organizationId).valid)
    throw Error("Baseline dossier integrity verification failed.");
  return report;
}
