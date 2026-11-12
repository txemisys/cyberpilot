import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { AssetScope } from "./assets-inventory-service";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import { OPERATOR_STEP_CODES, verifyOperatorSteps,
  verifyOperatorRun } from "./assets-offline-acceptance-run-service";
import type { OperatorStep, OperatorStepCode } from
  "./assets-offline-acceptance-run-service";

export type EvidenceReviewStatus =
  "NOT_CHECKED" | "REFERENCE_MATCHED" | "DISPUTED" | "STALE_REFERENCE";
export type EvidenceReviewCommand = {
  runId: string;
  stepCode: OperatorStepCode;
  expectedRunRevision: number;
  expectedEvidenceDigest: string;
  state: EvidenceReviewStatus;
  reason: string;
  referenceLocation: string | null;
  referenceObservedAt: string | null;
  crossCheckedIdentifiers: string[];
  limitations: string[];
};
export type EvidenceReviewRevisionCommand = EvidenceReviewCommand & {
  reviewId: string;
  expectedReviewRevision: number;
};
export type EvidenceReviewQuery = {
  runId: string;
  includeStale: boolean;
  includeOperatorReason: boolean;
};
export type EvidenceReviewIssue = {
  code: "STEP_NOT_RECORDED" | "REFERENCE_CHANGED" |
    "REVIEWER_SAME_AS_OPERATOR" | "SOURCE_REVISION_FUTURE" |
    "EVIDENCE_DIGEST_INVALID" | "REVIEWER_REASON_SHORT" |
    "MATCHED_WITHOUT_CROSSCHECK" | "REVIEW_STALE" |
    "REVIEW_DISPUTED" | "REVIEW_NOT_CHECKED";
  severity: "BLOCK" | "REVIEW";
  message: string;
};
export type EvidenceReviewAttestation = {
  schema: "cyberpilot.assets.evidence.review.attestation.v1";
  organizationId: string;
  runId: string;
  stepCode: OperatorStepCode;
  sourceRunRevision: number;
  currentRunRevision: number;
  evidenceDigest: string;
  currentEvidenceDigest: string | null;
  referenceStillMatches: boolean;
  reviewerIsIndependent: boolean;
  reviewerIdentityKnown: boolean;
  result: EvidenceReviewStatus;
  sourceVerified: boolean;
  externalSignatureVerified: false;
  operatorObservationAuthenticated: false;
  crossChecks: number;
  issues: EvidenceReviewIssue[];
  checkedAt: string;
  digest: string;
};
export type EvidenceReviewSummary = {
  schema: "cyberpilot.assets.evidence.review.summary.v1";
  organizationId: string;
  runId: string;
  runRevision: number;
  runState: string;
  totalSteps: number;
  evidenceRecorded: number;
  independentReferencesMatched: number;
  disputed: number;
  stale: number;
  missing: number;
  reviewed: number;
  readyForHumanSignoff: boolean;
  requiresHumanSignoff: true;
  externalOriginVerified: false;
  legalSignoffVerified: false;
  backupErasureVerified: false;
  mergeAuthorized: false;
  assessments: EvidenceReviewAttestation[];
  outstanding: Array<{ stepCode: OperatorStepCode;
    reason: string; nextAction: string }>;
  generatedAt: string;
  digest: string;
};
type StoredReview = {
  id: string; organizationId: string; acceptanceRunId: string;
  stepCode: string; sourceRunRevision: number;
  evidenceDigest: string; reviewState: string; revision: number;
  originalOperatorUserId: string; reviewerUserId: string;
  reviewerReason: string; referenceLocation: string | null;
  referenceObservedAt: Date | null; crossCheckedIdentifiers: unknown;
  limitations: unknown; createdAt: Date; updatedAt: Date;
};
type RunRow = {
  id: string; organizationId: string; revision: number;
  state: string; steps: unknown; operatorUserId: string;
};
const statuses: EvidenceReviewStatus[] = [
  "NOT_CHECKED", "REFERENCE_MATCHED", "DISPUTED", "STALE_REFERENCE",
];
const limits = [
  "A reviewer can corroborate a local reference, not authenticate its external creator.",
  "No SHA-256 digest is a digital signature.",
  "Independent means a different authenticated user from the operator who recorded the step.",
  "Stale or contested references block the next human signoff stage.",
  "A complete nine-step review cannot grant legal, privacy or backup erasure approval.",
];
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Evidence review requires a JSON object.");
  return value as Record<string, unknown>;
}
function allow(value: Record<string, unknown>, keys: string[]) {
  if (Object.keys(value).some(key => !keys.includes(key)))
    fail("INVALID", "Unexpected independent evidence review input field.");
}
function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid " + label + " identifier.");
  return value;
}
function reason(value: unknown): string {
  if (typeof value !== "string" || value.trim().length < 20 ||
      value.length > 1500 || /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "Evidence review needs 20–1500 characters of explanation.");
  return value.trim();
}
function revision(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > 2147483647)
    fail("INVALID", "Invalid positive evidence CAS revision.");
  return value;
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function validDigest(value: unknown): value is string {
  return typeof value === "string" &&
    /^[a-f0-9]{64}$/.test(value);
}
function sameHash(a: unknown, b: unknown): boolean {
  if (!validDigest(a) || !validDigest(b)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function timestamp(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    fail("INVALID", "Expected a UTC evidence-observed timestamp.");
  return new Date(value).toISOString();
}
function limitedText(value: unknown, maxItems: number) {
  if (!Array.isArray(value) || value.length > maxItems ||
      value.some(x => typeof x !== "string" ||
        x.trim().length < 6 || x.length > 250 ||
        /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    fail("INVALID", "Evidence cross-checks and caveats must be bounded and unique.");
  return value as string[];
}
function nullableLocation(value: unknown) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length < 8 ||
      value.length > 500 || /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "Reference location must be a bounded internal identifier.");
  return value;
}
function parseCommon(value: Record<string, unknown>): EvidenceReviewCommand {
  const stepCode = value.stepCode;
  if (!OPERATOR_STEP_CODES.includes(stepCode as OperatorStepCode))
    fail("INVALID", "Choose a fixed acceptance step.");
  if (!statuses.includes(value.state as EvidenceReviewStatus))
    fail("INVALID", "Unknown evidence review verdict.");
  if (!validDigest(value.expectedEvidenceDigest))
    fail("INVALID", "Expected the exact current reference SHA-256.");
  const crossCheckedIdentifiers = limitedText(
    value.crossCheckedIdentifiers ?? [], 20);
  if (value.state === "REFERENCE_MATCHED" &&
      crossCheckedIdentifiers.length < 1)
    fail("INVALID", "A matched reference needs an independently checked identifier.");
  return {
    runId: identifier(value.runId, "run"),
    stepCode: stepCode as OperatorStepCode,
    expectedRunRevision: revision(value.expectedRunRevision),
    expectedEvidenceDigest: value.expectedEvidenceDigest,
    state: value.state as EvidenceReviewStatus,
    reason: reason(value.reason),
    referenceLocation: nullableLocation(value.referenceLocation),
    referenceObservedAt: timestamp(value.referenceObservedAt),
    crossCheckedIdentifiers,
    limitations: limitedText(value.limitations ?? [], 20),
  };
}
export function parseEvidenceReviewCreate(raw: unknown):
  EvidenceReviewCommand {
  const value = object(raw);
  allow(value, ["runId", "stepCode", "expectedRunRevision",
    "expectedEvidenceDigest", "state", "reason",
    "referenceLocation", "referenceObservedAt",
    "crossCheckedIdentifiers", "limitations"]);
  return parseCommon(value);
}
export function parseEvidenceReviewRevision(raw: unknown):
  EvidenceReviewRevisionCommand {
  const value = object(raw);
  allow(value, ["reviewId", "expectedReviewRevision",
    "runId", "stepCode", "expectedRunRevision",
    "expectedEvidenceDigest", "state", "reason",
    "referenceLocation", "referenceObservedAt",
    "crossCheckedIdentifiers", "limitations"]);
  return {
    ...parseCommon(value),
    reviewId: identifier(value.reviewId, "review"),
    expectedReviewRevision: revision(value.expectedReviewRevision),
  };
}
export function parseEvidenceReviewQuery(raw: unknown):
  EvidenceReviewQuery {
  const value = object(raw);
  allow(value, ["runId", "includeStale", "includeOperatorReason"]);
  for (const name of ["includeStale", "includeOperatorReason"]) {
    if (value[name] !== undefined && typeof value[name] !== "boolean")
      fail("INVALID", "Invalid evidence review disclosure switch.");
  }
  return {
    runId: identifier(value.runId, "run"),
    includeStale: value.includeStale !== false,
    includeOperatorReason: value.includeOperatorReason === true,
  };
}
export function referenceFingerprint(step: OperatorStep): string {
  return hash({
    schema: "cyberpilot.assets.operator.evidence.reference.v1",
    code: step.code,
    status: step.status,
    evidenceId: step.evidenceId,
    evidenceDescription: step.evidenceDescription,
    recordedByUserId: step.recordedByUserId,
    recordedAt: step.recordedAt,
    reason: step.reason,
    limitations: step.limitations,
    attestationScope: step.attestationScope,
  });
}
export function inspectEvidenceReview(
  scope: { organizationId: string; runId: string; runRevision: number },
  step: OperatorStep | null, row: StoredReview | null,
  checkedAt = new Date(),
): EvidenceReviewAttestation {
  if (!Number.isFinite(checkedAt.getTime()))
    fail("INVALID", "Review verification clock invalid.");
  const issues: EvidenceReviewIssue[] = [];
  const issue = (code: EvidenceReviewIssue["code"],
    message: string, severity: EvidenceReviewIssue["severity"] = "BLOCK") =>
    issues.push({ code, message, severity });
  const referenceDigest = step ? referenceFingerprint(step) : null;
  const referenceStillMatches = !!row && !!referenceDigest &&
    sameHash(row.evidenceDigest, referenceDigest);
  const reviewerIsIndependent = !!row && !!step &&
    !!step.recordedByUserId &&
    row.reviewerUserId !== step.recordedByUserId &&
    row.reviewerUserId !== row.originalOperatorUserId;
  const reviewerIdentityKnown = !!row && !!row.reviewerUserId;
  if (!step || step.status !== "EVIDENCE_RECORDED")
    issue("STEP_NOT_RECORDED", "Operator step has no recorded source evidence.");
  if (row && !referenceStillMatches)
    issue("REFERENCE_CHANGED", "Local reference has changed since independent review.");
  if (row && !reviewerIsIndependent)
    issue("REVIEWER_SAME_AS_OPERATOR", "Reviewer must differ from the evidence author.");
  if (row && row.sourceRunRevision > scope.runRevision)
    issue("SOURCE_REVISION_FUTURE", "Review references a future operator CAS revision.");
  if (row && !validDigest(row.evidenceDigest))
    issue("EVIDENCE_DIGEST_INVALID", "Evidence fingerprint malformed.");
  if (row && row.reviewerReason.length < 20)
    issue("REVIEWER_REASON_SHORT", "Independent review reason is incomplete.");
  if (row?.reviewState === "REFERENCE_MATCHED" &&
      (!Array.isArray(row.crossCheckedIdentifiers) ||
       row.crossCheckedIdentifiers.length === 0))
    issue("MATCHED_WITHOUT_CROSSCHECK", "Matched reference has no checked identifiers.");
  if (row?.reviewState === "DISPUTED")
    issue("REVIEW_DISPUTED", "Independent reviewer disputed the source reference.");
  if (row?.reviewState === "STALE_REFERENCE")
    issue("REVIEW_STALE", "Independent reference is stale.");
  if (!row || row.reviewState === "NOT_CHECKED")
    issue("REVIEW_NOT_CHECKED", "No independent matching review has been completed.");
  const canonical = {
    schema: "cyberpilot.assets.evidence.review.attestation.v1" as const,
    organizationId: scope.organizationId,
    runId: scope.runId,
    stepCode: step?.code ??
      (row?.stepCode as OperatorStepCode) ?? "CSV_IMPORT_REVIEW",
    sourceRunRevision: row?.sourceRunRevision ?? 0,
    currentRunRevision: scope.runRevision,
    evidenceDigest: row?.evidenceDigest ?? "",
    currentEvidenceDigest: referenceDigest,
    referenceStillMatches,
    reviewerIsIndependent,
    reviewerIdentityKnown,
    result: (row?.reviewState ?? "NOT_CHECKED") as EvidenceReviewStatus,
    sourceVerified: issues.length === 0 &&
      row?.reviewState === "REFERENCE_MATCHED",
    externalSignatureVerified: false as const,
    operatorObservationAuthenticated: false as const,
    crossChecks: Array.isArray(row?.crossCheckedIdentifiers) ?
      row.crossCheckedIdentifiers.length : 0,
    issues,
    checkedAt: checkedAt.toISOString(),
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyEvidenceAttestation(
  report: EvidenceReviewAttestation,
): { valid: boolean; errors: string[] } {
  const { digest, ...canonical } = report;
  const errors: string[] = [];
  if (!sameHash(digest, hash(canonical)))
    errors.push("Independent evidence attestation digest invalid.");
  if (report.sourceVerified && (!report.referenceStillMatches ||
      !report.reviewerIsIndependent || report.result !== "REFERENCE_MATCHED" ||
      report.issues.length > 0))
    errors.push("Source verified flag conflicts with a mandatory blocker.");
  if (report.externalSignatureVerified !== false ||
      report.operatorObservationAuthenticated !== false)
    errors.push("Review falsely claims external signature or authenticity.");
  return { valid: errors.length === 0, errors };
}
export function summarizeIndependentReviews(input: {
  organizationId: string;
  runId: string;
  revision: number;
  state: string;
  steps: OperatorStep[];
  reviews: StoredReview[];
}, now = new Date()): EvidenceReviewSummary {
  const validation = verifyOperatorSteps(input.steps);
  if (!validation.valid)
    fail("CONFLICT", "Operator checklist is structurally invalid.");
  const byCode = new Map(input.reviews.map(item => [item.stepCode, item]));
  const assessments = input.steps.map(step => inspectEvidenceReview({
    organizationId: input.organizationId,
    runId: input.runId, runRevision: input.revision,
  }, step, byCode.get(step.code) ?? null, now));
  const independentReferencesMatched = assessments.filter(x =>
    x.sourceVerified).length;
  const disputed = assessments.filter(x => x.result === "DISPUTED").length;
  const stale = assessments.filter(x =>
    x.result === "STALE_REFERENCE" || x.issues.some(i =>
      i.code === "REFERENCE_CHANGED")).length;
  const missing = assessments.filter(x =>
    x.result === "NOT_CHECKED").length;
  const outstanding = assessments.filter(x => !x.sourceVerified).map(a => ({
    stepCode: a.stepCode,
    reason: a.issues.map(i => i.message).join(" "),
    nextAction: a.result === "DISPUTED" ?
      "Resolve conflict with a different responsible reviewer." :
      "Check the current operator reference independently and record a reason.",
  }));
  const canonical = {
    schema: "cyberpilot.assets.evidence.review.summary.v1" as const,
    organizationId: input.organizationId, runId: input.runId,
    runRevision: input.revision, runState: input.state,
    totalSteps: input.steps.length,
    evidenceRecorded: validation.completed,
    independentReferencesMatched,
    disputed, stale, missing,
    reviewed: input.reviews.length,
    readyForHumanSignoff:
      independentReferencesMatched === OPERATOR_STEP_CODES.length &&
      input.state === "EVIDENCE_CAPTURED",
    requiresHumanSignoff: true as const,
    externalOriginVerified: false as const,
    legalSignoffVerified: false as const,
    backupErasureVerified: false as const,
    mergeAuthorized: false as const,
    assessments, outstanding, generatedAt: now.toISOString(),
  };
  return { ...canonical, digest: hash(canonical) };
}
function toView(row: StoredReview) {
  return {
    ...row, referenceObservedAt:
      row.referenceObservedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    scope: "LOCAL_REFERENCE_CROSSCHECK_NOT_EXTERNAL_SIGNATURE",
    caveats: limits,
  };
}
async function authorizedRun(scope: AssetScope, runId: string) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Independent source review needs ADMIN or OWNER.");
  const run = await db.assetOfflineAcceptanceRun.findFirst({
    where: { id: runId, organizationId: scope.organizationId },
  });
  if (!run)
    fail("MISSING", "Operator acceptance run not found in this organization.");
  const check = verifyOperatorRun(run);
  if (!check.valid)
    fail("CONFLICT", "Operator acceptance run failed structural validation.");
  const steps = verifyOperatorSteps(run.steps).items;
  return { run, steps };
}
function validateReviewer(scope: AssetScope, step: OperatorStep,
  state: EvidenceReviewStatus) {
  if (step.status !== "EVIDENCE_RECORDED")
    fail("CONFLICT", "A source reference must exist before review.");
  if (!step.recordedByUserId || step.recordedByUserId === scope.userId)
    fail("FORBIDDEN", "A person cannot independently review their own evidence.");
  if (state === "REFERENCE_MATCHED" && !step.evidenceId)
    fail("CONFLICT", "No specific evidence reference exists to corroborate.");
}
export async function createIndependentEvidenceReview(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  const command = parseEvidenceReviewCreate(raw);
  const { run, steps } = await authorizedRun(scope, command.runId);
  if (run.revision !== command.expectedRunRevision)
    fail("CONFLICT", "Source operator run CAS revision changed.");
  const step = steps.find(x => x.code === command.stepCode)!;
  validateReviewer(scope, step, command.state);
  const fingerprint = referenceFingerprint(step);
  if (!sameHash(fingerprint, command.expectedEvidenceDigest))
    fail("CONFLICT", "Source step reference fingerprint changed.");
  if (command.referenceObservedAt &&
      Date.parse(command.referenceObservedAt) > now.getTime())
    fail("INVALID", "Source reference cannot be observed in the future.");
  const where = {
    organizationId: scope.organizationId,
    acceptanceRunId: run.id,
    stepCode: command.stepCode,
  };
  const existing = await db.assetEvidenceReview.findUnique({
    where: { organizationId_acceptanceRunId_stepCode: where },
  });
  if (existing) {
    if (sameHash(existing.evidenceDigest, fingerprint) &&
        existing.reviewState === command.state &&
        existing.reviewerUserId === scope.userId)
      return { replayed: true, review: toView(existing) };
    fail("CONFLICT", "Independent review already exists; use a revisioned update.");
  }
  try {
    const created = await db.$transaction(async tx => {
      const active = await tx.assetOfflineAcceptanceRun.findFirst({
        where: { id: run.id, organizationId: scope.organizationId,
          revision: command.expectedRunRevision },
      });
      if (!active) fail("CONFLICT", "Source run advanced during evidence review.");
      const row = await tx.assetEvidenceReview.create({ data: {
        ...where, sourceRunRevision: run.revision,
        evidenceDigest: fingerprint,
        reviewState: command.state, revision: 1,
        originalOperatorUserId: step.recordedByUserId!,
        reviewerUserId: scope.userId,
        reviewerReason: command.reason,
        referenceLocation: command.referenceLocation,
        referenceObservedAt: command.referenceObservedAt ?
          new Date(command.referenceObservedAt) : null,
        crossCheckedIdentifiers: command.crossCheckedIdentifiers,
        limitations: command.limitations,
      } });
      await tx.auditEvent.create({ data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assetEvidence.review.created",
        resourceType: "AssetEvidenceReview", resourceId: row.id,
        metadata: {
          schema: "cyberpilot.assets.evidence.review.audit.v1",
          runId: run.id, stepCode: command.stepCode,
          sourceRunRevision: run.revision,
          evidenceDigest: fingerprint, state: command.state,
          reviewerId: scope.userId,
          operatorId: step.recordedByUserId,
          reason: command.reason,
          crossChecks: command.crossCheckedIdentifiers.length,
          externalSignatureVerified: false,
          independentLegalSignoffGranted: false,
        },
      } });
      return row;
    });
    return { replayed: false, review: toView(created) };
  } catch (cause) {
    const current = await db.assetEvidenceReview.findUnique({
      where: { organizationId_acceptanceRunId_stepCode: where },
    });
    if (current && sameHash(current.evidenceDigest, fingerprint) &&
        current.reviewState === command.state &&
        current.reviewerUserId === scope.userId)
      return { replayed: true, review: toView(current) };
    if (current) fail("CONFLICT", "Concurrent independent review differs.");
    throw cause;
  }
}
export async function reviseIndependentEvidenceReview(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  const command = parseEvidenceReviewRevision(raw);
  const { run, steps } = await authorizedRun(scope, command.runId);
  if (run.revision !== command.expectedRunRevision)
    fail("CONFLICT", "Operator run revision changed.");
  const step = steps.find(x => x.code === command.stepCode)!;
  validateReviewer(scope, step, command.state);
  const fingerprint = referenceFingerprint(step);
  if (!sameHash(fingerprint, command.expectedEvidenceDigest))
    fail("CONFLICT", "Evidence source reference has changed.");
  const old = await db.assetEvidenceReview.findFirst({
    where: { id: command.reviewId,
      organizationId: scope.organizationId,
      acceptanceRunId: command.runId,
      stepCode: command.stepCode },
  });
  if (!old) fail("MISSING", "Independent review not found in this tenant.");
  if (old.revision !== command.expectedReviewRevision)
    fail("CONFLICT", "Independent review CAS revision changed.");
  const updated = await db.$transaction(async tx => {
    const active = await tx.assetOfflineAcceptanceRun.findFirst({
      where: { id: run.id, organizationId: scope.organizationId,
        revision: run.revision },
    });
    if (!active) fail("CONFLICT", "Source run revision changed during review.");
    const result = await tx.assetEvidenceReview.updateMany({
      where: {
        id: old.id, organizationId: scope.organizationId,
        revision: old.revision, reviewState: old.reviewState,
        evidenceDigest: old.evidenceDigest,
      },
      data: {
        revision: { increment: 1 },
        sourceRunRevision: run.revision,
        evidenceDigest: fingerprint,
        reviewState: command.state,
        reviewerUserId: scope.userId,
        originalOperatorUserId: step.recordedByUserId!,
        reviewerReason: command.reason,
        referenceLocation: command.referenceLocation,
        referenceObservedAt: command.referenceObservedAt ?
          new Date(command.referenceObservedAt) : null,
        crossCheckedIdentifiers: command.crossCheckedIdentifiers,
        limitations: command.limitations,
      },
    });
    if (result.count !== 1)
      fail("CONFLICT", "Concurrent independent review CAS conflict.");
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assetEvidence.review.revised",
      resourceType: "AssetEvidenceReview",
      resourceId: old.id,
      metadata: {
        schema: "cyberpilot.assets.evidence.review.audit.v1",
        runId: run.id, stepCode: command.stepCode,
        revisionBefore: old.revision, revisionAfter: old.revision + 1,
        from: old.reviewState, to: command.state,
        previousDigest: old.evidenceDigest,
        evidenceDigest: fingerprint,
        sourceRunRevision: run.revision,
        operatorId: step.recordedByUserId,
        reviewerId: scope.userId,
        reason: command.reason,
        externalSignatureVerified: false,
        independentLegalSignoffGranted: false,
      },
    } });
    return tx.assetEvidenceReview.findUniqueOrThrow({
      where: { id: old.id },
    });
  });
  return { review: toView(updated), replayed: false };
}
export async function listIndependentEvidenceReviews(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  const options = parseEvidenceReviewQuery(raw);
  const { run, steps } = await authorizedRun(scope, options.runId);
  const reviews = await db.assetEvidenceReview.findMany({
    where: { organizationId: scope.organizationId,
      acceptanceRunId: run.id },
    orderBy: [{ stepCode: "asc" }],
    take: OPERATOR_STEP_CODES.length + 1,
  });
  if (reviews.length > OPERATOR_STEP_CODES.length)
    fail("CONFLICT", "Review register exceeds the fixed checklist size.");
  const report = summarizeIndependentReviews({
    organizationId: scope.organizationId, runId: run.id,
    revision: run.revision, state: run.state,
    steps, reviews,
  }, now);
  if (!options.includeStale && report.stale > 0)
    fail("CONFLICT", "Stale evidence exists and cannot be silently omitted.");
  return {
    ...report,
    reviews: reviews.map(row => ({
      ...toView(row),
      reviewerReason: options.includeOperatorReason ?
        row.reviewerReason : "[redacted; request disclosure explicitly]",
    })),
    caveats: limits,
  };
}
export function independenceReconciliationPlan(report: EvidenceReviewSummary) {
  return report.outstanding.map(item => ({
    stepCode: item.stepCode,
    sourceStatus: report.assessments.find(a =>
      a.stepCode === item.stepCode)?.result ?? "NOT_CHECKED",
    reason: item.reason,
    action: item.nextAction,
    urgency: item.reason.includes("changed") ||
      item.reason.includes("disputed") ? "BLOCK" : "REVIEW",
    automatedApprovalAllowed: false as const,
  }));
}
