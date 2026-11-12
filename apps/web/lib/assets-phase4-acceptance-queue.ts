import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { AssetScope } from "./assets-inventory-service";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import {
  OPERATOR_STEP_CODES, verifyOperatorRun, verifyOperatorSteps,
} from "./assets-offline-acceptance-run-service";
import {
  referenceFingerprint, inspectEvidenceReview,
} from "./assets-evidence-independent-review";

export type QueueSeverity = "BLOCK" | "REVIEW" | "INFO";
export type QueueSignalCode =
  "SOURCE_INCONSISTENT" | "CHECKLIST_INVALID" | "STEPS_INCOMPLETE" |
  "STEPS_BLOCKED" | "RUN_NOT_SUBMITTED" | "AUDIT_MISSING" |
  "AUDIT_EXCESS" | "AUDIT_REVISION_MISMATCH" | "INDEPENDENT_REVIEW_MISSING" |
  "INDEPENDENT_REVIEW_DISPUTED" | "INDEPENDENT_REVIEW_STALE" |
  "INDEPENDENT_SELF_REVIEW" | "INDEPENDENT_REFERENCE_CHANGED" |
  "INDEPENDENT_CROSSCHECK_MISSING" | "RUN_AGE_LIMIT" |
  "REVIEW_AGE_LIMIT" | "PRIVACY_DECISION_PENDING" |
  "RETENTION_EXCEPTION_OPEN" | "RELEASE_DECISION_MISSING" |
  "RELEASE_DECISION_PENDING" | "PROVIDER_LIVE_EXCLUDED" |
  "BACKUP_APPROVAL_PENDING" | "MANUAL_SIGNOFF_PENDING" |
  "AUDIT_RESOURCE_MISMATCH" | "REVIEW_IDENTITY_MISMATCH" |
  "REVIEW_REVISION_INVALID";
export type QueueSignal = {
  code: QueueSignalCode;
  severity: QueueSeverity;
  entityId: string | null;
  explanation: string;
  nextAction: string;
  requiresIndependentHuman: boolean;
  cannotBeResolvedBySyntheticFixtures: boolean;
};
export type QueueRun = {
  runId: string;
  organizationId: string;
  importId: string;
  inspectionId: string;
  state: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  submittedAt: string | null;
  ageDays: number;
  recordedSteps: number;
  blockedSteps: number;
  missingSteps: string[];
  operatorIdentityVerifiedLocally: boolean;
  runIntegrityVerified: boolean;
  sourceDigest: string;
  dossierDigest: string;
  independentReviewCount: number;
  independentMatchedCount: number;
  independentDisputedCount: number;
  independentStaleCount: number;
  selfReviewedCount: number;
  auditCount: number;
  auditExpected: number;
  auditCompleteWithinCount: boolean;
  retentionReviewState: string | null;
  releaseReviewState: string | null;
  signals: QueueSignal[];
  blockers: number;
  humanActions: number;
  readyForIndependentSignoffCheck: boolean;
  acceptedByProduct: false;
  externalProviderVerified: false;
  privacyLegallyApproved: false;
  backupsErased: false;
  mergeAuthorized: false;
};
export type QueuePolicy = {
  maxRuns: number;
  offset: number;
  maxAgeDays: number;
  maxReviewerAgeDays: number;
  includeDrafts: boolean;
  includeCompleted: boolean;
  includeHumanReasons: boolean;
  maxAuditsPerRun: number;
};
export type AcceptanceQueueReport = {
  schema: "cyberpilot.assets.phase4.acceptance.queue.v1";
  organizationId: string;
  generatedAt: string;
  policy: QueuePolicy;
  totalMatching: number;
  returned: number;
  moreResults: boolean;
  rows: QueueRun[];
  summary: {
    drafts: number;
    inProgress: number;
    blocked: number;
    evidenceCaptured: number;
    reopened: number;
    integrityFailures: number;
    missingReviewEvidence: number;
    staleReviewEvidence: number;
    selfReviewIncidents: number;
    auditGaps: number;
    outstandingHumanActions: number;
    blockedRuns: number;
    locallyReviewReady: number;
    coverage: "PAGE_ONLY";
  };
  priorities: Array<{
    runId: string;
    severity: QueueSeverity;
    leadingSignals: QueueSignalCode[];
    nextActions: string[];
    ownerRole: "ADMIN" | "INDEPENDENT_REVIEWER" |
      "PRIVACY_OWNER" | "PRODUCT_OWNER";
    autoEscalated: false;
  }>;
  digest: string;
  dataAccess: "TENANT_SCOPED_READ_ONLY";
  readOnly: true;
  externalTenantsRequired: false;
  liveProviderRequests: 0;
  manualAcceptanceRecordedByQueue: false;
  legalApprovalInferred: false;
  backupErasureInferred: false;
  automaticMergeAllowed: false;
  limitations: string[];
};
type RunRow = {
  id: string; organizationId: string;
  importId: string; inspectionId: string;
  idempotencyKey: string; dossierDigest: string;
  sourceDigest: string; state: string; revision: number;
  operatorUserId: string; openingReason: string;
  steps: unknown; limitations: unknown;
  humanAcknowledgements: unknown;
  completedSteps: number; blockedSteps: number;
  startedAt: Date; updatedAt: Date; submittedAt: Date | null;
  submittedByUserId: string | null; submittedReason: string | null;
};
type ReviewRow = {
  id: string; organizationId: string; acceptanceRunId: string;
  stepCode: string; sourceRunRevision: number;
  evidenceDigest: string; reviewState: string; revision: number;
  originalOperatorUserId: string; reviewerUserId: string;
  reviewerReason: string; referenceLocation: string | null;
  referenceObservedAt: Date | null; crossCheckedIdentifiers: unknown;
  limitations: unknown; createdAt: Date; updatedAt: Date;
};
type AuditRow = {
  id: string; organizationId: string;
  resourceType: string; resourceId: string | null;
  action: string; actorUserId: string | null; actorType: string;
  occurredAt: Date; metadata: unknown;
};
const limitations = [
  "This dashboard inspects only the requested tenant and bounded page of its recorded runs.",
  "Page totals do not represent all assets or vulnerability exposure across an organization.",
  "A reference match is internal corroboration, not independent authentication of source origin.",
  "This queue cannot approve retention law, provider LIVE, backup erasure or operational product acceptance.",
  "The number of audit events is not sufficient to establish complete CAS integrity by itself.",
  "All dates are checked relative to the supplied evaluation clock, never a background scheduler.",
  "A ready-to-review status is an invitation for human review, not an approval.",
  "The report digest is local integrity evidence and not an external signature.",
];
const actionMap: Record<QueueSignalCode, string> = {
  SOURCE_INCONSISTENT: "Investigate changed or invalid source digests before review.",
  CHECKLIST_INVALID: "Inspect invalid fixed-step evidence and recover using an audited transition.",
  STEPS_INCOMPLETE: "Perform and document remaining real offline walk-through steps.",
  STEPS_BLOCKED: "Investigate every blocked operator step with a responsible human.",
  RUN_NOT_SUBMITTED: "Submit complete local evidence for independent human review.",
  AUDIT_MISSING: "Investigate missing operator audit entries without fabricating events.",
  AUDIT_EXCESS: "Inspect event history exceeding the bounded acceptance limit.",
  AUDIT_REVISION_MISMATCH: "Reconstruct CAS revision sequence and identify missing or duplicate actions.",
  INDEPENDENT_REVIEW_MISSING: "Have a different authorized human corroborate each step.",
  INDEPENDENT_REVIEW_DISPUTED: "Resolve contested reference with separate documented evidence.",
  INDEPENDENT_REVIEW_STALE: "Recheck expired references without overwriting history.",
  INDEPENDENT_SELF_REVIEW: "Reassign independent verification to someone other than the evidence author.",
  INDEPENDENT_REFERENCE_CHANGED: "Reconcile reviewer fingerprint against the current operator reference.",
  INDEPENDENT_CROSSCHECK_MISSING: "Collect at least one independently checked local identifier.",
  RUN_AGE_LIMIT: "Re-evaluate aged operator evidence against current source snapshots.",
  REVIEW_AGE_LIMIT: "Refresh old independent review evidence and its provenance.",
  PRIVACY_DECISION_PENDING: "Obtain responsible privacy review for applicable policies and PII.",
  RETENTION_EXCEPTION_OPEN: "Resolve or explicitly document remaining retention exceptions.",
  RELEASE_DECISION_MISSING: "Create and audit a source-bound manual release review.",
  RELEASE_DECISION_PENDING: "Require an authorized human decision on the release review.",
  PROVIDER_LIVE_EXCLUDED: "Leave external provider acceptance in a separate LIVE scope.",
  BACKUP_APPROVAL_PENDING: "Document and independently approve backup and exported-copy handling.",
  MANUAL_SIGNOFF_PENDING: "Obtain genuine human product acceptance; never auto-approve.",
  AUDIT_RESOURCE_MISMATCH: "Check tenant, resource identity and audit actor binding.",
  REVIEW_IDENTITY_MISMATCH: "Investigate a review linked to the wrong operator run or step.",
  REVIEW_REVISION_INVALID: "Inspect inconsistent independent review revision or actor metadata.",
};
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    invalid("Acceptance queue options must be an object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, name: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    invalid("Invalid queue " + name + ".");
  return value;
}
function flag(value: unknown, name: string, fallback: boolean) {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") invalid("Invalid queue flag " + name + ".");
  return value;
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equals(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function days(then: Date, now: Date) {
  return Math.max(0, Math.floor((now.getTime() - then.getTime()) / 86400000));
}
function signal(code: QueueSignalCode, severity: QueueSeverity,
  explanation: string, entityId: string | null = null): QueueSignal {
  return {
    code, severity, entityId, explanation, nextAction: actionMap[code],
    requiresIndependentHuman: [
      "INDEPENDENT_REVIEW_MISSING", "INDEPENDENT_REVIEW_DISPUTED",
      "INDEPENDENT_SELF_REVIEW", "PRIVACY_DECISION_PENDING",
      "BACKUP_APPROVAL_PENDING", "MANUAL_SIGNOFF_PENDING",
      "RELEASE_DECISION_PENDING",
    ].includes(code),
    cannotBeResolvedBySyntheticFixtures: code !== "PROVIDER_LIVE_EXCLUDED",
  };
}
export function parseAcceptanceQueuePolicy(raw: unknown = {}): QueuePolicy {
  const input = object(raw);
  const accepted = ["maxRuns", "offset", "maxAgeDays",
    "maxReviewerAgeDays", "includeDrafts", "includeCompleted",
    "includeHumanReasons", "maxAuditsPerRun"];
  if (Object.keys(input).some(key => !accepted.includes(key)))
    invalid("Unknown acceptance queue property.");
  return {
    maxRuns: integer(input.maxRuns ?? 20, "page size", 1, 50),
    offset: integer(input.offset ?? 0, "offset", 0, 100000),
    maxAgeDays: integer(input.maxAgeDays ?? 30, "age", 1, 3650),
    maxReviewerAgeDays: integer(input.maxReviewerAgeDays ?? 14,
      "review age", 1, 3650),
    includeDrafts: flag(input.includeDrafts, "includeDrafts", true),
    includeCompleted: flag(input.includeCompleted, "includeCompleted", true),
    includeHumanReasons: flag(input.includeHumanReasons,
      "includeHumanReasons", false),
    maxAuditsPerRun: integer(input.maxAuditsPerRun ?? 100,
      "audit limit", 1, 1000),
  };
}
export function assessAcceptanceQueueRun(input: {
  row: RunRow;
  reviews: ReviewRow[];
  audits: AuditRow[];
  releaseState: string | null;
  retentionState: string | null;
  policy: QueuePolicy;
  now: Date;
}): QueueRun {
  const { row, reviews, audits, policy, now } = input;
  if (!Number.isFinite(now.getTime()))
    invalid("Queue inspection clock must be valid.");
  const signals: QueueSignal[] = [];
  const add = (code: QueueSignalCode, severity: QueueSeverity,
    explanation: string, id: string | null = row.id) =>
    signals.push(signal(code, severity, explanation, id));
  const verified = verifyOperatorRun(row);
  const steps = verifyOperatorSteps(row.steps);
  if (!verified.valid || !steps.valid)
    add("CHECKLIST_INVALID", "BLOCK",
      "Operator state, fixed checklist or persisted counters are invalid.");
  if (!equals(row.sourceDigest, row.sourceDigest) ||
      !equals(row.dossierDigest, row.dossierDigest))
    add("SOURCE_INCONSISTENT", "BLOCK",
      "Stored source and dossier digests must be canonical SHA-256.");
  if (steps.completed < OPERATOR_STEP_CODES.length)
    add("STEPS_INCOMPLETE", "BLOCK",
      "Only " + steps.completed + " of nine operator stages have evidence.");
  if (steps.blocked)
    add("STEPS_BLOCKED", "BLOCK",
      steps.blocked + " operator steps explicitly block acceptance.");
  if (row.state !== "EVIDENCE_CAPTURED")
    add("RUN_NOT_SUBMITTED", "BLOCK",
      "Current state is " + row.state + ", not EVIDENCE_CAPTURED.");
  if (days(row.updatedAt, now) > policy.maxAgeDays)
    add("RUN_AGE_LIMIT", "REVIEW",
      "Operator evidence was last updated outside the selected age window.");
  if (audits.length === 0)
    add("AUDIT_MISSING", "BLOCK", "No operator audit entries exist.");
  if (audits.length > policy.maxAuditsPerRun)
    add("AUDIT_EXCESS", "BLOCK", "Audit history exceeds bounded inspection.");
  if (audits.length !== row.revision)
    add("AUDIT_REVISION_MISMATCH", "BLOCK",
      "Observed audit count does not equal CAS revision.");
  if (audits.some(event =>
    event.organizationId !== row.organizationId ||
    event.resourceId !== row.id ||
    event.resourceType !== "AssetOfflineAcceptanceRun" ||
    event.actorUserId === null))
    add("AUDIT_RESOURCE_MISMATCH", "BLOCK",
      "Audit actor or tenant/resource identity was inconsistent.");
  const matched = new Set<string>();
  let disputed = 0, stale = 0, self = 0;
  const knownSteps = new Map(steps.items.map(step => [step.code, step]));
  const seen = new Set<string>();
  for (const review of reviews) {
    const step = knownSteps.get(review.stepCode);
    if (seen.has(review.stepCode) || !step ||
        review.organizationId !== row.organizationId ||
        review.acceptanceRunId !== row.id) {
      add("REVIEW_IDENTITY_MISMATCH", "BLOCK",
        "Independent review does not match a unique current source step.",
        review.id);
      continue;
    }
    seen.add(review.stepCode);
    const assessment = inspectEvidenceReview({
      organizationId: row.organizationId,
      runId: row.id, runRevision: row.revision,
    }, step, review, now);
    if (!assessment.reviewerIsIndependent) {
      self++;
      add("INDEPENDENT_SELF_REVIEW", "BLOCK",
        "Review actor is the author of the recorded source.", review.id);
    }
    if (!assessment.referenceStillMatches) {
      stale++;
      add("INDEPENDENT_REFERENCE_CHANGED", "BLOCK",
        "Operator source fingerprint differs from independent review.", review.id);
    }
    if (review.reviewState === "DISPUTED") {
      disputed++;
      add("INDEPENDENT_REVIEW_DISPUTED", "BLOCK",
        "Independent reference was explicitly disputed.", review.id);
    }
    if (review.reviewState === "STALE_REFERENCE" ||
        days(review.updatedAt, now) > policy.maxReviewerAgeDays) {
      stale++;
      add("INDEPENDENT_REVIEW_STALE", "REVIEW",
        "Evidence review is stale under the chosen policy.", review.id);
    }
    if (!Array.isArray(review.crossCheckedIdentifiers) ||
        review.crossCheckedIdentifiers.length === 0)
      add("INDEPENDENT_CROSSCHECK_MISSING", "BLOCK",
        "No independently checked identifier was recorded.", review.id);
    if (review.revision < 1 ||
        !review.reviewerUserId || !review.originalOperatorUserId)
      add("REVIEW_REVISION_INVALID", "BLOCK",
        "Revision or authenticated actor is missing.", review.id);
    if (assessment.sourceVerified &&
        days(review.updatedAt, now) <= policy.maxReviewerAgeDays)
      matched.add(review.stepCode);
  }
  if (matched.size !== OPERATOR_STEP_CODES.length)
    add("INDEPENDENT_REVIEW_MISSING", "BLOCK",
      "Only " + matched.size + " of nine current steps are independently matched.");
  if (!input.releaseState)
    add("RELEASE_DECISION_MISSING", "BLOCK",
      "No source-bound release decision exists for this import/inspection.");
  else if (input.releaseState !== "ACCEPTED_OFFLINE")
    add("RELEASE_DECISION_PENDING", "REVIEW",
      "Release decision status: " + input.releaseState + ".");
  if (!input.retentionState)
    add("PRIVACY_DECISION_PENDING", "REVIEW",
      "Retention/PII exception review is not recorded for the import.");
  else if (input.retentionState !== "DOCUMENTED_WITH_EXCEPTIONS")
    add("RETENTION_EXCEPTION_OPEN", "REVIEW",
      "Retention exception review status: " + input.retentionState + ".");
  add("BACKUP_APPROVAL_PENDING", "REVIEW",
    "Backup and export lifecycle requires separate actual human approval.");
  add("MANUAL_SIGNOFF_PENDING", "REVIEW",
    "No product acceptance can be inferred from queue rows.");
  add("PROVIDER_LIVE_EXCLUDED", "INFO",
    "Provider LIVE is intentionally outside the offline scope.");
  const blockers = signals.filter(s => s.severity === "BLOCK").length;
  const humanActions = signals.filter(s => s.severity === "REVIEW").length;
  return {
    runId: row.id, organizationId: row.organizationId,
    importId: row.importId, inspectionId: row.inspectionId,
    state: row.state, revision: row.revision,
    createdAt: row.startedAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    submittedAt: row.submittedAt?.toISOString() ?? null,
    ageDays: days(row.updatedAt, now),
    recordedSteps: steps.completed, blockedSteps: steps.blocked,
    missingSteps: steps.items.filter(s =>
      s.status !== "EVIDENCE_RECORDED").map(s => s.code),
    operatorIdentityVerifiedLocally: !!row.operatorUserId,
    runIntegrityVerified: verified.valid,
    sourceDigest: row.sourceDigest, dossierDigest: row.dossierDigest,
    independentReviewCount: reviews.length,
    independentMatchedCount: matched.size,
    independentDisputedCount: disputed,
    independentStaleCount: stale,
    selfReviewedCount: self,
    auditCount: audits.length, auditExpected: row.revision,
    auditCompleteWithinCount: audits.length === row.revision &&
      audits.length <= policy.maxAuditsPerRun,
    retentionReviewState: input.retentionState,
    releaseReviewState: input.releaseState,
    signals, blockers, humanActions,
    readyForIndependentSignoffCheck:
      blockers === 0 && row.state === "EVIDENCE_CAPTURED" &&
      matched.size === OPERATOR_STEP_CODES.length,
    acceptedByProduct: false, externalProviderVerified: false,
    privacyLegallyApproved: false, backupsErased: false,
    mergeAuthorized: false,
  };
}
export function assembleAcceptanceQueue(input: {
  organizationId: string;
  policy: QueuePolicy;
  rows: QueueRun[];
  total: number;
  evaluatedAt: Date;
}): AcceptanceQueueReport {
  if (!Number.isFinite(input.evaluatedAt.getTime()))
    invalid("Queue evaluation clock invalid.");
  if (input.total < input.rows.length ||
      input.rows.length > input.policy.maxRuns ||
      input.rows.some(row => row.organizationId !== input.organizationId))
    invalid("Queue result scope or pagination is inconsistent.");
  const rows = input.rows;
  const summary = {
    drafts: rows.filter(r => r.state === "DRAFT").length,
    inProgress: rows.filter(r => r.state === "IN_PROGRESS").length,
    blocked: rows.filter(r => r.state === "BLOCKED").length,
    evidenceCaptured: rows.filter(r => r.state === "EVIDENCE_CAPTURED").length,
    reopened: rows.filter(r => r.state === "REOPENED").length,
    integrityFailures: rows.filter(r => !r.runIntegrityVerified).length,
    missingReviewEvidence: rows.filter(r =>
      r.independentMatchedCount < 9).length,
    staleReviewEvidence: rows.filter(r =>
      r.independentStaleCount > 0).length,
    selfReviewIncidents: rows.filter(r => r.selfReviewedCount > 0).length,
    auditGaps: rows.filter(r => !r.auditCompleteWithinCount).length,
    outstandingHumanActions: rows.reduce((sum, row) =>
      sum + row.humanActions, 0),
    blockedRuns: rows.filter(r => r.blockers > 0).length,
    locallyReviewReady: rows.filter(r =>
      r.readyForIndependentSignoffCheck).length,
    coverage: "PAGE_ONLY" as const,
  };
  const priorities = rows.filter(r => r.signals.length > 0)
    .sort((a, b) => b.blockers - a.blockers ||
      b.humanActions - a.humanActions ||
      a.runId.localeCompare(b.runId))
    .map(r => ({
      runId: r.runId,
      severity: (r.blockers ? "BLOCK" : r.humanActions ?
        "REVIEW" : "INFO") as QueueSeverity,
      leadingSignals: r.signals.slice(0, 6).map(s => s.code),
      nextActions: [...new Set(r.signals.map(s => s.nextAction))].slice(0, 6),
      ownerRole: (r.selfReviewedCount > 0 ||
        r.independentMatchedCount < 9 ? "INDEPENDENT_REVIEWER" :
        !r.retentionReviewState ? "PRIVACY_OWNER" :
        r.blockers ? "ADMIN" : "PRODUCT_OWNER") as
        "ADMIN" | "INDEPENDENT_REVIEWER" | "PRIVACY_OWNER" |
        "PRODUCT_OWNER",
      autoEscalated: false as const,
    }));
  const canonical = {
    schema: "cyberpilot.assets.phase4.acceptance.queue.v1" as const,
    organizationId: input.organizationId,
    generatedAt: input.evaluatedAt.toISOString(),
    policy: input.policy,
    totalMatching: input.total, returned: rows.length,
    moreResults: input.policy.offset + rows.length < input.total,
    rows, summary, priorities,
    dataAccess: "TENANT_SCOPED_READ_ONLY" as const,
    readOnly: true as const,
    externalTenantsRequired: false as const,
    liveProviderRequests: 0 as const,
    manualAcceptanceRecordedByQueue: false as const,
    legalApprovalInferred: false as const,
    backupErasureInferred: false as const,
    automaticMergeAllowed: false as const,
  };
  return { ...canonical, digest: hash(canonical), limitations };
}
export function verifyAcceptanceQueue(report: AcceptanceQueueReport) {
  const { digest, limitations: caveats, ...canonical } = report;
  const issues: string[] = [];
  if (!equals(digest, hash(canonical)))
    issues.push("Queue digest was altered.");
  if (report.returned !== report.rows.length ||
      report.rows.length > report.policy.maxRuns ||
      report.rows.some(r => r.organizationId !== report.organizationId))
    issues.push("Queue page or tenant scope is inconsistent.");
  if (report.summary.blockedRuns !== report.rows.filter(r =>
    r.blockers > 0).length)
    issues.push("Queue summary differs from blocker count.");
  if (report.rows.some(r =>
    r.acceptedByProduct || r.mergeAuthorized ||
    r.privacyLegallyApproved || r.backupsErased))
    issues.push("A row claims an unsupported external action.");
  if (report.automaticMergeAllowed ||
      report.manualAcceptanceRecordedByQueue ||
      report.legalApprovalInferred || report.backupErasureInferred ||
      report.liveProviderRequests !== 0 ||
      report.readOnly !== true)
    issues.push("Queue claims unsupported writes or approvals.");
  if (!Array.isArray(caveats) || caveats.length < 6)
    issues.push("Queue limitations were removed.");
  return { valid: issues.length === 0, issues };
}
export function acceptanceQueueActionPlan(report: AcceptanceQueueReport) {
  if (!verifyAcceptanceQueue(report).valid)
    throw new WorkInputError("CONFLICT",
      "Cannot export altered queue action plan.");
  return report.priorities.map((item, index) => ({
    rankWithinPage: index + 1,
    ...item,
    verifiedByHuman: false as const,
    actionExecuted: false as const,
    writeAttempted: false as const,
  }));
}
export async function inspectAcceptanceQueue(scope: AssetScope,
  raw: unknown = {}, now = new Date()) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Phase 4 acceptance queue requires ADMIN or OWNER.");
  const policy = parseAcceptanceQueuePolicy(raw);
  const where = {
    organizationId: scope.organizationId,
    ...(!policy.includeDrafts || !policy.includeCompleted ? {
      state: { notIn: [
        ...(!policy.includeDrafts ? ["DRAFT"] : []),
        ...(!policy.includeCompleted ? ["EVIDENCE_CAPTURED"] : []),
      ] },
    } : {}),
  };
  const [total, runs] = await Promise.all([
    db.assetOfflineAcceptanceRun.count({ where }),
    db.assetOfflineAcceptanceRun.findMany({
      where, orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      take: policy.maxRuns, skip: policy.offset,
    }),
  ]);
  const rows = await Promise.all(runs.map(async row => {
    const [reviews, audits, retention, release] = await Promise.all([
      db.assetEvidenceReview.findMany({
        where: { organizationId: scope.organizationId,
          acceptanceRunId: row.id },
        take: OPERATOR_STEP_CODES.length + 1,
        orderBy: { stepCode: "asc" },
      }),
      db.auditEvent.findMany({
        where: { organizationId: scope.organizationId,
          resourceType: "AssetOfflineAcceptanceRun",
          resourceId: row.id },
        take: policy.maxAuditsPerRun + 1,
        orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
      }),
      db.assetRetentionReview.findFirst({
        where: { organizationId: scope.organizationId,
          importId: row.importId },
        select: { state: true },
      }),
      db.assetReleaseReview.findFirst({
        where: { organizationId: scope.organizationId,
          importId: row.importId, inspectionId: row.inspectionId },
        select: { state: true },
      }),
    ]);
    return assessAcceptanceQueueRun({
      row, reviews, audits,
      releaseState: release?.state ?? null,
      retentionState: retention?.state ?? null,
      policy, now,
    });
  }));
  const result = assembleAcceptanceQueue({
    organizationId: scope.organizationId,
    policy, rows, total, evaluatedAt: now,
  });
  if (!verifyAcceptanceQueue(result).valid)
    throw new WorkInputError("CONFLICT",
      "Generated queue failed internal verification.");
  return result;
}
