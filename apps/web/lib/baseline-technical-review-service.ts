import { db, type Prisma } from "@cyberpilot/database";
import {
  sha256V2, canonicalV2,
  verifyBaselineReportV2,
  type BaselineReportV2,
} from "@cyberpilot/risk-engine";

/**
 * Technical/development acceptance review for declarative Baseline.
 * A TECHNICALLY_REVIEWED status means the report and reviewer notes
 * were checked internally. It does NOT establish external evidence,
 * customer approval, CIS certification or actual remediation.
 */
export type ReviewActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type ReviewFindingKind =
  "MISSING_EVIDENCE" | "SOURCE_INCONSISTENT" |
  "CLARIFICATION_REQUIRED" | "SCOPE_UNCLEAR" |
  "CONTROL_UNANSWERED" | "REPORT_INTEGRITY" |
  "REVIEW_NOTE";
export type ReviewFinding = {
  id: string;
  questionId: string | null;
  kind: ReviewFindingKind;
  severity: "BLOCKING" | "FOLLOW_UP" | "INFORMATIONAL";
  status: "OPEN" | "ADDRESSED" | "ACCEPTED_AS_UNKNOWN";
  observation: string;
  proposedAction: string;
  evidenceReference: string | null;
  reviewerValidatedTechnicalControl: false;
  customerConfirmed: false;
};
export type ReviewCommand = {
  operation: "CREATE" | "READ" | "LIST" | "UPDATE" |
    "START" | "REQUEST_CHANGES" | "COMPLETE" |
    "REOPEN" | "HISTORY" | "COMPARE";
  sourceRevision?: number;
  expectedRevision?: number;
  reviewId?: string;
  findings?: ReviewFinding[];
  reviewerUserId?: string | null;
  limit?: number;
  olderReviewId?: string;
};
export type ReviewView = {
  id: string; organizationId: string;
  draftId: string; sourceRevision: number;
  reportDigest: string; questionnaireVersion: 1;
  revision: number; state: "OPEN" | "IN_REVIEW" |
    "CHANGES_REQUESTED" | "TECHNICALLY_REVIEWED" | "REOPENED";
  scope: "DEVELOPMENT_REVIEW";
  findings: ReviewFinding[];
  findingsDigest: string;
  issueCount: number; blockingIssueCount: number;
  reviewerUserId: string | null;
  completedAt: string | null;
  createdAt: string; updatedAt: string;
  externalCustomerApproval: false;
  securityControlsIndependentlyVerified: 0;
  cisCertification: false;
  historicalCyberScoreModified: false;
};
export type ReviewResult = {
  schema: "cyberpilot.baseline.technical.review.service.v1";
  organizationId: string;
  operation: ReviewCommand["operation"];
  data: unknown;
  legalAcceptanceRecorded: false;
  independentEvidenceVerified: false;
  remediationExecuted: false;
  legacyCyberScoreModified: false;
};
export class ReviewConflictError extends Error {
  constructor() { super("Technical review changed; reload version."); }
}
const stateNames = [
  "OPEN","IN_REVIEW","CHANGES_REQUESTED",
  "TECHNICALLY_REVIEWED","REOPENED",
] as const;
const kinds = [
  "MISSING_EVIDENCE","SOURCE_INCONSISTENT","CLARIFICATION_REQUIRED",
  "SCOPE_UNCLEAR","CONTROL_UNANSWERED","REPORT_INTEGRITY","REVIEW_NOTE",
] as const;
const severity = ["BLOCKING","FOLLOW_UP","INFORMATIONAL"] as const;
const findingStates = ["OPEN","ADDRESSED","ACCEPTED_AS_UNKNOWN"] as const;
const stateTransitions: Record<ReviewView["state"],
  ReviewView["state"][]> = {
    OPEN: ["IN_REVIEW","CHANGES_REQUESTED"],
    IN_REVIEW: ["CHANGES_REQUESTED","TECHNICALLY_REVIEWED"],
    CHANGES_REQUESTED: ["IN_REVIEW"],
    TECHNICALLY_REVIEWED: ["REOPENED"],
    REOPENED: ["IN_REVIEW","CHANGES_REQUESTED"],
  };
function fail(reason: string): never {
  throw Error("Baseline review: " + reason);
}
function safeId(x: unknown): x is string {
  return typeof x === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
}
function findingText(x: unknown, max: number) {
  return typeof x === "string" && x.length >= 1 &&
    x.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(x);
}
function sha(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function sanitizeFindings(raw: unknown): ReviewFinding[] {
  if (!Array.isArray(raw) || raw.length > 80)
    fail("Invalid number of review findings.");
  const seen = new Set<string>();
  return raw.map(item => {
    if (!item || typeof item !== "object" || Array.isArray(item))
      fail("Malformed review finding.");
    const x = item as Record<string, unknown>;
    const fields = [
      "id","questionId","kind","severity","status",
      "observation","proposedAction","evidenceReference",
      "reviewerValidatedTechnicalControl","customerConfirmed",
    ];
    if (Object.keys(x).some(k => !fields.includes(k)))
      fail("Unexpected review finding property.");
    if (!safeId(x.id) || seen.has(x.id) ||
        !kinds.includes(x.kind as ReviewFindingKind) ||
        !severity.includes(x.severity as ReviewFinding["severity"]) ||
        !findingStates.includes(x.status as ReviewFinding["status"]) ||
        x.questionId !== null && (
          typeof x.questionId !== "string" ||
          !/^[a-z][a-z0-9-]{2,79}$/.test(x.questionId)) ||
        !findingText(x.observation, 750) ||
        !findingText(x.proposedAction, 750) ||
        x.evidenceReference !== null && (
          typeof x.evidenceReference !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,95}$/.test(x.evidenceReference)) ||
        x.reviewerValidatedTechnicalControl !== false ||
        x.customerConfirmed !== false)
      fail("Invalid or falsely certified review finding.");
    seen.add(x.id);
    return {
      id: x.id, questionId: x.questionId as string | null,
      kind: x.kind as ReviewFindingKind,
      severity: x.severity as ReviewFinding["severity"],
      status: x.status as ReviewFinding["status"],
      observation: x.observation as string,
      proposedAction: x.proposedAction as string,
      evidenceReference: x.evidenceReference as string | null,
      reviewerValidatedTechnicalControl: false as const,
      customerConfirmed: false as const,
    };
  }).sort((a, b) => a.id.localeCompare(b.id));
}
function parse(raw: unknown): ReviewCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected review command.");
  const x = raw as Record<string, unknown>;
  const fields = [
    "operation","sourceRevision","expectedRevision",
    "reviewId","findings","reviewerUserId","limit","olderReviewId",
  ];
  if (Object.keys(x).some(k => !fields.includes(k)))
    fail("Unexpected review field.");
  const operations: ReviewCommand["operation"][] = [
    "CREATE","READ","LIST","UPDATE","START",
    "REQUEST_CHANGES","COMPLETE","REOPEN","HISTORY","COMPARE",
  ];
  if (!operations.includes(x.operation as ReviewCommand["operation"]))
    fail("Unknown review operation.");
  const c: ReviewCommand = {
    operation: x.operation as ReviewCommand["operation"],
  };
  if (x.sourceRevision !== undefined) {
    if (typeof x.sourceRevision !== "number" ||
        !Number.isSafeInteger(x.sourceRevision) ||
        x.sourceRevision < 1 || x.sourceRevision > 1e7)
      fail("Invalid source revision.");
    c.sourceRevision = x.sourceRevision;
  }
  if (x.expectedRevision !== undefined) {
    if (typeof x.expectedRevision !== "number" ||
        !Number.isSafeInteger(x.expectedRevision) ||
        x.expectedRevision < 1 || x.expectedRevision > 1e7)
      fail("Invalid compare-and-swap revision.");
    c.expectedRevision = x.expectedRevision;
  }
  if (x.reviewId !== undefined) {
    if (!safeId(x.reviewId)) fail("Invalid review ID.");
    c.reviewId = x.reviewId;
  }
  if (x.olderReviewId !== undefined) {
    if (!safeId(x.olderReviewId)) fail("Invalid comparison source.");
    c.olderReviewId = x.olderReviewId;
  }
  if (x.findings !== undefined)
    c.findings = sanitizeFindings(x.findings);
  if (x.reviewerUserId !== undefined) {
    if (x.reviewerUserId !== null && !safeId(x.reviewerUserId))
      fail("Reviewer must be a member.");
    c.reviewerUserId = x.reviewerUserId as string | null;
  }
  if (x.limit !== undefined) {
    if (typeof x.limit !== "number" || !Number.isSafeInteger(x.limit) ||
        x.limit < 1 || x.limit > 100)
      fail("Invalid result limit.");
    c.limit = x.limit;
  }
  if (c.operation === "CREATE" && !c.sourceRevision)
    fail("A submitted source revision is required.");
  if (!["CREATE","LIST"].includes(c.operation) && !c.reviewId)
    fail("Review ID required.");
  if (["UPDATE","START","REQUEST_CHANGES","COMPLETE","REOPEN"]
    .includes(c.operation) && !c.expectedRevision)
    fail("Optimistic revision required.");
  if (c.operation === "COMPARE" && !c.olderReviewId)
    fail("Comparison needs an earlier review.");
  return c;
}
function view(row: {
  id: string; organizationId: string;
  draftId: string; sourceRevision: number;
  reportDigest: string; questionnaireVersion: number;
  revision: number; state: string; scope: string;
  reviewNotes: unknown; issueCount: number;
  blockingIssueCount: number;
  reviewerUserId: string | null; completedAt: Date | null;
  createdAt: Date; updatedAt: Date;
}): ReviewView {
  const findings = sanitizeFindings(row.reviewNotes);
  if (row.questionnaireVersion !== 1 ||
      row.scope !== "DEVELOPMENT_REVIEW" ||
      !stateNames.includes(row.state as ReviewView["state"]) ||
      row.issueCount !== findings.length ||
      row.blockingIssueCount !== findings.filter(x =>
        x.severity === "BLOCKING" && x.status === "OPEN").length ||
      !/^[a-f0-9]{64}$/.test(row.reportDigest))
    fail("Stored technical review integrity invalid.");
  return {
    id: row.id, organizationId: row.organizationId,
    draftId: row.draftId, sourceRevision: row.sourceRevision,
    reportDigest: row.reportDigest, questionnaireVersion: 1,
    revision: row.revision,
    state: row.state as ReviewView["state"],
    scope: "DEVELOPMENT_REVIEW",
    findings, findingsDigest: sha(findings),
    issueCount: row.issueCount,
    blockingIssueCount: row.blockingIssueCount,
    reviewerUserId: row.reviewerUserId,
    completedAt: row.completedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    externalCustomerApproval: false,
    securityControlsIndependentlyVerified: 0,
    cisCertification: false, historicalCyberScoreModified: false,
  };
}
async function authorize(actor: ReviewActor, mutate: boolean) {
  if (!safeId(actor.organizationId) || !safeId(actor.userId))
    fail("Invalid actor scope.");
  const membership = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId,
      userId: actor.userId,
    }, select: { role: true },
  });
  if (!membership || membership.role !== actor.role)
    fail("Current organization membership is required.");
  if (mutate && !["OWNER","ADMIN","AUDITOR"].includes(membership.role))
    fail("Review modifications require reviewer or administrator role.");
}
async function audit(
  tx: Prisma.TransactionClient, actor: ReviewActor,
  review: {
    id: string; revision: number; state: string;
    reviewNotes: unknown;
  }, priorState: string, action: string,
) {
  const notes = sanitizeFindings(review.reviewNotes);
  await tx.baselineReviewEvent.create({
    data: {
      organizationId: actor.organizationId,
      reviewId: review.id, revision: review.revision,
      action, previousState: priorState,
      newState: review.state,
      findingsDigest: sha(notes),
      actorUserId: actor.userId,
      metadata: {
        issues: notes.length,
        openBlocking: notes.filter(x =>
          x.status === "OPEN" && x.severity === "BLOCKING").length,
        independentSecurityVerification: false,
        customerAuthorization: false,
        scoreMutation: false,
      },
    },
  });
  await tx.auditEvent.create({
    data: {
      organizationId: actor.organizationId,
      actorType: "USER", actorUserId: actor.userId,
      action: "BASELINE_TECH_REVIEW_" + action,
      resourceType: "BASELINE_TECHNICAL_REVIEW",
      resourceId: review.id,
      metadata: {
        revision: review.revision,
        state: review.state,
        noteDigest: sha(notes),
        submittedCustomerApproval: false,
        securityCertification: false,
        accountMutations: 0,
      },
    },
  });
}
export class BaselineTechnicalReviewService {
  async execute(actor: ReviewActor,
    raw: unknown): Promise<ReviewResult> {
    const command = parse(raw);
    const mutate = !["READ","LIST","HISTORY","COMPARE"]
      .includes(command.operation);
    await authorize(actor, mutate);
    const data = await this.dispatch(actor, command);
    return {
      schema: "cyberpilot.baseline.technical.review.service.v1",
      organizationId: actor.organizationId,
      operation: command.operation, data,
      legalAcceptanceRecorded: false,
      independentEvidenceVerified: false,
      remediationExecuted: false, legacyCyberScoreModified: false,
    };
  }
  private async dispatch(actor: ReviewActor,
    command: ReviewCommand): Promise<unknown> {
    const organizationId = actor.organizationId;
    if (command.operation === "LIST") {
      const rows = await db.baselineReview.findMany({
        where: { organizationId },
        orderBy: { updatedAt: "desc" },
        take: command.limit ?? 50,
      });
      return {
        reviews: rows.map(view), securityCertificates: 0,
      };
    }
    if (command.operation === "CREATE") {
      const draft = await db.baselineDraft.findFirst({
        where: { organizationId, questionnaireVersion: 1 },
      });
      if (!draft) fail("No organization Baseline exists.");
      const revision = await db.baselineRevision.findFirst({
        where: {
          organizationId, draftId: draft.id,
          revision: command.sourceRevision!,
          eventKind: "SUBMIT",
        },
      });
      if (!revision?.report || !revision.reportDigest)
        fail("Only submitted Baseline revisions can be reviewed.");
      const report = revision.report as BaselineReportV2;
      if (!verifyBaselineReportV2(report).valid ||
          report.organizationId !== organizationId ||
          report.digest !== revision.reportDigest ||
          report.summary.securityScore !== null)
        fail("Submitted evidence digest invalid or foreign.");
      return db.$transaction(async tx => {
        const existed = await tx.baselineReview.findUnique({
          where: { organizationId_draftId_sourceRevision: {
            organizationId, draftId: draft.id,
            sourceRevision: command.sourceRevision!,
          } },
        });
        if (existed)
          return {
            review: view(existed), alreadyExists: true,
            customerApprovalCaptured: false,
          };
        const row = await tx.baselineReview.create({
          data: {
            organizationId, draftId: draft.id,
            sourceRevision: revision.revision,
            reportDigest: revision.reportDigest!,
            state: "OPEN", scope: "DEVELOPMENT_REVIEW",
            reviewNotes: [],
            issueCount: 0, blockingIssueCount: 0,
            revision: 1, createdById: actor.userId,
            updatedById: actor.userId,
          },
        });
        await audit(tx, actor, row, "NONE", "CREATE");
        return {
          review: view(row), alreadyExists: false,
          customerApprovalCaptured: false,
        };
      }, { isolationLevel: "Serializable" });
    }
    const row = await db.baselineReview.findFirst({
      where: { id: command.reviewId, organizationId },
    });
    if (!row) fail("Review not found in current organization.");
    if (command.operation === "READ") return { review: view(row) };
    if (command.operation === "HISTORY") {
      const events = await db.baselineReviewEvent.findMany({
        where: { organizationId, reviewId: row.id },
        orderBy: { revision: "desc" },
        take: command.limit ?? 50,
      });
      return {
        review: view(row),
        events: events.map(x => ({
          revision: x.revision, action: x.action,
          previousState: x.previousState, newState: x.newState,
          findingsDigest: x.findingsDigest,
          actorUserId: x.actorUserId,
          at: x.createdAt.toISOString(),
          customerApproved: false,
        })),
      };
    }
    if (command.operation === "COMPARE") {
      const older = await db.baselineReview.findFirst({
        where: {
          id: command.olderReviewId, organizationId,
          draftId: row.draftId,
        },
      });
      if (!older || older.sourceRevision >= row.sourceRevision)
        fail("Review comparison requires earlier submitted source.");
      const old = view(older), newer = view(row);
      const olderIds = new Set(old.findings.map(x => x.id));
      const newerIds = new Set(newer.findings.map(x => x.id));
      return {
        olderReviewId: old.id, newerReviewId: newer.id,
        sourceRevisionDelta: newer.sourceRevision - old.sourceRevision,
        newFindings: [...newerIds].filter(x => !olderIds.has(x)),
        absentFindings: [...olderIds].filter(x => !newerIds.has(x)),
        newlyReportedClosed: new Set(newer.findings.filter(x =>
          x.status !== "OPEN").map(x => x.id)).size,
        actualRemediationIndependentlyVerified: false,
        reductionInTechnicalRiskEstablished: false,
      };
    }
    if (row.revision !== command.expectedRevision)
      throw new ReviewConflictError();
    const priorState = row.state as ReviewView["state"];
    const desired: ReviewView["state"] =
      command.operation === "START" ? "IN_REVIEW" :
      command.operation === "REQUEST_CHANGES" ?
        "CHANGES_REQUESTED" :
      command.operation === "COMPLETE" ? "TECHNICALLY_REVIEWED" :
      command.operation === "REOPEN" ? "REOPENED" :
        priorState;
    if (desired !== priorState &&
        !stateTransitions[priorState].includes(desired))
      fail("Invalid review state transition.");
    if (command.operation === "UPDATE" &&
        priorState === "TECHNICALLY_REVIEWED")
      fail("Reopen a completed internal review before updating.");
    const findings = command.findings ?? sanitizeFindings(row.reviewNotes);
    const blocking = findings.filter(x => x.status === "OPEN" &&
      x.severity === "BLOCKING").length;
    if (command.operation === "COMPLETE" && blocking > 0)
      fail("Blocking unresolved reviewer findings remain.");
    const reviewer = command.reviewerUserId === undefined ?
      row.reviewerUserId : command.reviewerUserId;
    if (reviewer) {
      const member = await db.membership.findFirst({
        where: { organizationId, userId: reviewer },
        select: { role: true },
      });
      if (!member || !["OWNER","ADMIN","AUDITOR"].includes(member.role))
        fail("Review assignee must be current authorized reviewer.");
    }
    return db.$transaction(async tx => {
      const updated = await tx.baselineReview.update({
        where: { id: row.id, revision: row.revision },
        data: {
          revision: row.revision + 1,
          state: desired, reviewerUserId: reviewer,
          issueCount: findings.length, blockingIssueCount: blocking,
          reviewNotes: findings as Prisma.InputJsonValue,
          updatedById: actor.userId,
          completedAt: desired === "TECHNICALLY_REVIEWED" ?
            new Date() : null,
        },
      });
      await audit(tx, actor, updated, priorState, command.operation);
      return {
        review: view(updated),
        auditWritten: true,
        developmentReviewOnly: true,
        externalCustomerSignoff: false,
        independentlyVerifiedTechnicalControls: 0,
      };
    }, { isolationLevel: "Serializable" });
  }
}
