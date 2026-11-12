import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import { OPERATOR_STEP_CODES, verifyOperatorRun,
  verifyOperatorSteps } from "./assets-offline-acceptance-run-service";
import { referenceFingerprint, inspectEvidenceReview,
  summarizeIndependentReviews } from "./assets-evidence-independent-review";

export type ReconciliationIssueCode =
  "MISSING_AUDIT" | "TRUNCATED_AUDIT" | "DUPLICATE_REVISION" |
  "REVISION_GAP" | "REVISION_OUT_OF_ORDER" | "MALFORMED_EVENT" |
  "FOREIGN_TENANT" | "INCORRECT_RESOURCE" | "UNEXPECTED_ACTION" |
  "ACTOR_MISSING" | "ACTOR_MISMATCH" | "EVIDENCE_REFERENCE_MISMATCH" |
  "SOURCE_DIGEST_MISMATCH" | "STATE_MISMATCH" |
  "COUNTER_MISMATCH" | "TERMINAL_WITHOUT_SUBMISSION" |
  "SELF_REVIEW" | "REVIEW_STALE" | "REVIEW_DISPUTED" |
  "REVIEW_WITHOUT_EVIDENCE" | "REVIEW_AUDIT_MISSING" |
  "REVIEW_REVISION_GAP" | "REVIEW_AUDIT_MISMATCH" |
  "RUN_INTEGRITY_FAILED" | "REVIEW_IDENTITY_MISMATCH" |
  "REVIEW_DIGEST_INVALID" | "AUDIT_UNSUPPORTED_CLAIM";
export type ReconciliationIssue = {
  code: ReconciliationIssueCode;
  severity: "BLOCK" | "REVIEW";
  entity: "RUN" | "STEP" | "EVIDENCE_REVIEW";
  resourceId: string | null;
  auditId: string | null;
  revision: number | null;
  detail: string;
  nextAction: string;
};
export type ReconciledEvent = {
  id: string;
  resourceType: string;
  resourceId: string | null;
  organizationId: string;
  action: string;
  operation: string;
  createdAt: string;
  actorUserId: string | null;
  revisionBefore: number | null;
  revisionAfter: number | null;
  sourceDigest: string | null;
  dossierDigest: string | null;
  stepCode: string | null;
  evidenceId: string | null;
  from: string | null;
  to: string | null;
  issues: ReconciliationIssue[];
};
export type ReconciledReview = {
  id: string;
  stepCode: string;
  state: string;
  revision: number;
  sourceRunRevision: number;
  reviewerUserId: string;
  originalOperatorUserId: string;
  currentReferenceMatches: boolean;
  independentlyReviewed: boolean;
  auditEvents: number;
  issueCodes: ReconciliationIssueCode[];
};
export type AuditReconciliationReport = {
  schema: "cyberpilot.assets.acceptance.audit.reconciliation.v1";
  organizationId: string;
  runId: string;
  checkedAt: string;
  state: string;
  revision: number;
  sourceDigest: string;
  dossierDigest: string;
  totalRunEvents: number;
  totalReviewEvents: number;
  runAuditComplete: boolean;
  reviewAuditComplete: boolean;
  runStateConsistent: boolean;
  reviewReferencesCurrent: boolean;
  evidenceReviewsComplete: boolean;
  evidenceIndependenceComplete: boolean;
  independentlyReviewedSteps: number;
  recordedSteps: number;
  reviewCount: number;
  events: ReconciledEvent[];
  reviews: ReconciledReview[];
  issues: ReconciliationIssue[];
  blockers: number;
  warnings: number;
  localAuditIntegrityVerified: boolean;
  readyForIndependentHumanDecision: boolean;
  externallySigned: false;
  legallyApproved: false;
  backupsErased: false;
  providerLiveChecked: false;
  phaseClosed: false;
  mergeAuthorized: false;
  noDatabaseWrites: true;
  digest: string;
  limitations: string[];
};
export type ReconciliationOptions = {
  runId: string;
  maximumRunEvents: number;
  maximumReviewEvents: number;
  includeEventDetails: boolean;
};
type Run = {
  id: string;
  organizationId: string;
  importId: string;
  inspectionId: string;
  revision: number;
  state: string;
  sourceDigest: string;
  dossierDigest: string;
  operatorUserId: string;
  idempotencyKey: string;
  openingReason: string;
  limitations: unknown;
  humanAcknowledgements: unknown;
  updatedAt: Date;
  steps: unknown;
  completedSteps: number;
  blockedSteps: number;
  startedAt: Date;
  submittedAt: Date | null;
  submittedByUserId: string | null;
  submittedReason: string | null;
};
type Review = {
  id: string;
  organizationId: string;
  acceptanceRunId: string;
  stepCode: string;
  sourceRunRevision: number;
  evidenceDigest: string;
  reviewState: string;
  revision: number;
  originalOperatorUserId: string;
  reviewerUserId: string;
  reviewerReason: string;
  referenceLocation: string | null;
  referenceObservedAt: Date | null;
  crossCheckedIdentifiers: unknown;
  limitations: unknown;
  createdAt: Date;
  updatedAt: Date;
};
type Event = {
  id: string;
  organizationId: string;
  resourceType: string;
  resourceId: string | null;
  action: string;
  actorType: string;
  actorUserId: string | null;
  metadata: unknown;
  occurredAt: Date;
};
const explanations: Record<ReconciliationIssueCode, string> = {
  MISSING_AUDIT: "Locate missing transaction audit; never fabricate an audit event.",
  TRUNCATED_AUDIT: "Increase the permitted bounded query or investigate oversized event history.",
  DUPLICATE_REVISION: "Investigate duplicate audit CAS revision and event idempotency.",
  REVISION_GAP: "Reconcile the missing audit revisions with transaction and backup history.",
  REVISION_OUT_OF_ORDER: "Inspect audit timestamp and CAS ordering without rewriting history.",
  MALFORMED_EVENT: "Inspect the versioned transaction metadata and its origin.",
  FOREIGN_TENANT: "Verify tenant isolation and quarantine foreign-scoped evidence.",
  INCORRECT_RESOURCE: "Reconcile the resource identity and audit relationship.",
  UNEXPECTED_ACTION: "Investigate an unknown operation before interpreting its result.",
  ACTOR_MISSING: "Identify why a human action lacks an authenticated user actor.",
  ACTOR_MISMATCH: "Check authenticated event actor against the persisted reviewer.",
  EVIDENCE_REFERENCE_MISMATCH: "Re-run reference verification against current operator evidence.",
  SOURCE_DIGEST_MISMATCH: "Compare source and dossier digests across transactions.",
  STATE_MISMATCH: "Reconcile reconstructed lifecycle and persisted state.",
  COUNTER_MISMATCH: "Investigate recorded and blocked counters against individual steps.",
  TERMINAL_WITHOUT_SUBMISSION: "Require the complete nine-step record and real human submission.",
  SELF_REVIEW: "Require a different authenticated reviewer for this evidence.",
  REVIEW_STALE: "Revisit a stale evidence reference, maintaining its original audit.",
  REVIEW_DISPUTED: "Resolve the disputed reference with a different responsible reviewer.",
  REVIEW_WITHOUT_EVIDENCE: "Record actual operator evidence before independently reviewing it.",
  REVIEW_AUDIT_MISSING: "Locate the review creation and revision events.",
  REVIEW_REVISION_GAP: "Investigate missing or repeated independent-review CAS revisions.",
  REVIEW_AUDIT_MISMATCH: "Compare independent review state and recorded audit transitions.",
  RUN_INTEGRITY_FAILED: "Repair inconsistency by a new audited decision, never a silent edit.",
  REVIEW_IDENTITY_MISMATCH: "Investigate review actor, step and scoped acceptance-run identity.",
  REVIEW_DIGEST_INVALID: "Recompute evidence reference digest from its original recorded step.",
  AUDIT_UNSUPPORTED_CLAIM: "Remove unsupported LIVE, legal, merge or external-signature claims.",
};
const limits = [
  "Only tenant-local PostgreSQL events and locally recorded references are reconstructed.",
  "Missing or truncated event histories invalidate the corresponding chain.",
  "SHA-256 equality is not an external signature or an identity attestation.",
  "A different authenticated reviewer is necessary but not sufficient for real-world approval.",
  "The evaluation neither contacts providers nor changes source audit records.",
  "Acceptance, legal signoff, backup erasure and permission to merge remain separate human decisions.",
];
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function object(value: unknown): Record<string, unknown> | null {
  if (!value || Array.isArray(value) || typeof value !== "object")
    return null;
  return value as Record<string, unknown>;
}
function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
function int(v: unknown): number | null {
  return typeof v === "number" && Number.isSafeInteger(v) ? v : null;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function eq(a: unknown, b: unknown) {
  if (typeof a !== "string" || typeof b !== "string" ||
      !/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b))
    return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function issue(code: ReconciliationIssueCode,
  entity: ReconciliationIssue["entity"],
  resourceId: string | null = null,
  auditId: string | null = null,
  revision: number | null = null,
  severity: ReconciliationIssue["severity"] = "BLOCK"): ReconciliationIssue {
  return {
    code, entity, resourceId, auditId, revision, severity,
    detail: code.replaceAll("_", " ").toLowerCase(),
    nextAction: explanations[code],
  };
}
export function parseReconciliationOptions(raw: unknown): ReconciliationOptions {
  const v = object(raw);
  if (!v) fail("INVALID", "Reconciliation requires a JSON object.");
  if (Object.keys(v).some(k => ![
    "runId", "maximumRunEvents", "maximumReviewEvents",
    "includeEventDetails",
  ].includes(k)))
    fail("INVALID", "Unexpected reconciliation option.");
  if (typeof v.runId !== "string" ||
      !/^[A-Za-z0-9_-]{5,150}$/.test(v.runId))
    fail("INVALID", "Invalid acceptance run identifier.");
  const bound = (v: unknown): number => {
    if (typeof v !== "number" || !Number.isSafeInteger(v) ||
        v < 1 || v > 1000)
      fail("INVALID", "Reconciliation limit must be between 1 and 1000.");
    return v;
  };
  if (v.includeEventDetails !== undefined &&
      typeof v.includeEventDetails !== "boolean")
    fail("INVALID", "Invalid event disclosure setting.");
  return {
    runId: v.runId,
    maximumRunEvents: bound(v.maximumRunEvents ?? 250),
    maximumReviewEvents: bound(v.maximumReviewEvents ?? 250),
    includeEventDetails: v.includeEventDetails === true,
  };
}
function normalizeEvent(row: Event): ReconciledEvent {
  const m = object(row.metadata);
  const created = row.action === "assetAcceptance.run.created" ||
    row.action === "assetEvidence.review.created";
  const before = created ? 0 : int(m?.revisionBefore);
  const after = created ? int(m?.revision) ?? 1 : int(m?.revisionAfter);
  const ownIssues: ReconciliationIssue[] = [];
  if (!m || !(str(m.schema)?.startsWith("cyberpilot.assets.") ||
      str(m.schema)?.startsWith("cyberpilot.assets.operator.")))
    ownIssues.push(issue("MALFORMED_EVENT", "RUN",
      row.resourceId, row.id, after));
  if (row.actorType !== "USER" || !row.actorUserId)
    ownIssues.push(issue("ACTOR_MISSING", "RUN",
      row.resourceId, row.id, after));
  if (before === null || after === null || before !== after - 1 ||
      after < 1)
    ownIssues.push(issue("MALFORMED_EVENT", "RUN",
      row.resourceId, row.id, after));
  if (m?.mergeAuthorized === true ||
      m?.signedOff === true ||
      m?.externalProviderValidated === true ||
      m?.externalSignatureVerified === true ||
      m?.independentLegalSignoffGranted === true)
    ownIssues.push(issue("AUDIT_UNSUPPORTED_CLAIM", "RUN",
      row.resourceId, row.id, after));
  return {
    id: row.id, resourceType: row.resourceType,
    resourceId: row.resourceId, organizationId: row.organizationId,
    action: row.action,
    operation: row.action.split(".").at(-1) ?? "UNKNOWN",
    createdAt: row.occurredAt.toISOString(),
    actorUserId: row.actorUserId,
    revisionBefore: before, revisionAfter: after,
    sourceDigest: str(m?.sourceDigest),
    dossierDigest: str(m?.dossierDigest),
    stepCode: str(m?.stepCode),
    evidenceId: str(m?.evidenceId),
    from: created ? null : str(m?.from),
    to: created ? str(m?.state) : str(m?.to),
    issues: ownIssues,
  };
}
function auditTimeline(rows: Event[], entity: "RUN" | "EVIDENCE_REVIEW",
  resourceId: string, tenant: string,
  expectedRevision: number,
  allowedActions: string[],
) {
  const ordered = [...rows].sort((a, b) =>
    a.occurredAt.getTime() - b.occurredAt.getTime() ||
    a.id.localeCompare(b.id));
  const events = ordered.map(normalizeEvent);
  const problems: ReconciliationIssue[] = [];
  let revision = 1;
  const seen = new Set<number>();
  for (const ev of events) {
    for (const item of ev.issues)
      problems.push({ ...item, entity });
    if (ev.organizationId !== tenant)
      problems.push(issue("FOREIGN_TENANT", entity, resourceId, ev.id,
        ev.revisionAfter));
    if (ev.resourceId !== resourceId)
      problems.push(issue("INCORRECT_RESOURCE", entity, resourceId, ev.id,
        ev.revisionAfter));
    if (!allowedActions.includes(ev.action))
      problems.push(issue("UNEXPECTED_ACTION", entity, resourceId, ev.id,
        ev.revisionAfter));
    if (ev.revisionAfter !== null && seen.has(ev.revisionAfter))
      problems.push(issue("DUPLICATE_REVISION", entity, resourceId, ev.id,
        ev.revisionAfter));
    if (ev.revisionAfter !== null) seen.add(ev.revisionAfter);
    if (ev.revisionAfter !== revision)
      problems.push(issue(ev.revisionAfter !== null &&
        ev.revisionAfter < revision ? "REVISION_OUT_OF_ORDER" :
        "REVISION_GAP", entity, resourceId, ev.id, ev.revisionAfter));
    if (ev.revisionBefore !== revision - 1)
      problems.push(issue("REVISION_GAP", entity, resourceId, ev.id,
        ev.revisionAfter));
    revision++;
  }
  if (!events.length)
    problems.push(issue("MISSING_AUDIT", entity, resourceId));
  if (revision - 1 !== expectedRevision)
    problems.push(issue("REVISION_GAP", entity, resourceId, null,
      expectedRevision));
  return { events, issues: problems,
    complete: problems.length === 0 && events.length === expectedRevision };
}
export function reconstructAcceptanceAudit(input: {
  run: Run;
  reviews: Review[];
  runEvents: Event[];
  reviewEvents: Event[];
  runTotal: number;
  reviewTotal: number;
  checkedAt: Date;
}): AuditReconciliationReport {
  const { run, reviews, runEvents, reviewEvents } = input;
  if (!Number.isFinite(input.checkedAt.getTime()))
    fail("INVALID", "Reconciliation evaluation clock is invalid.");
  const initial = verifyOperatorRun(run);
  const steps = verifyOperatorSteps(run.steps);
  const issues: ReconciliationIssue[] = [];
  if (!initial.valid || !steps.valid)
    issues.push(issue("RUN_INTEGRITY_FAILED", "RUN", run.id));
  if (steps.completed !== run.completedSteps ||
      steps.blocked !== run.blockedSteps)
    issues.push(issue("COUNTER_MISMATCH", "RUN", run.id));
  if (input.runTotal !== runEvents.length ||
      input.reviewTotal !== reviewEvents.length)
    issues.push(issue("TRUNCATED_AUDIT", "RUN", run.id));
  const timeline = auditTimeline(runEvents, "RUN", run.id,
    run.organizationId, run.revision,
    ["assetAcceptance.run.created", "assetAcceptance.run.start",
      "assetAcceptance.run.record_evidence", "assetAcceptance.run.block_step",
      "assetAcceptance.run.reset_step",
      "assetAcceptance.run.submit_for_independent_review",
      "assetAcceptance.run.reopen"]);
  issues.push(...timeline.issues);
  const known = new Set(reviews.map(r => r.id));
  for (const ev of reviewEvents)
    if (!ev.resourceId || !known.has(ev.resourceId))
      issues.push(issue("INCORRECT_RESOURCE",
        "EVIDENCE_REVIEW", ev.resourceId, ev.id));
  const verifiedReviews: ReconciledReview[] = [];
  const unique = new Set<string>();
  for (const row of reviews) {
    const step = steps.items.find(s => s.code === row.stepCode) ?? null;
    const evidenceMatches = !!step &&
      eq(row.evidenceDigest, referenceFingerprint(step));
    const scoped = row.organizationId === run.organizationId &&
      row.acceptanceRunId === run.id &&
      OPERATOR_STEP_CODES.includes(row.stepCode as typeof OPERATOR_STEP_CODES[number]);
    if (!scoped || unique.has(row.stepCode))
      issues.push(issue("REVIEW_IDENTITY_MISMATCH", "EVIDENCE_REVIEW",
        row.id));
    unique.add(row.stepCode);
    const relevant = reviewEvents.filter(ev =>
      ev.resourceId === row.id);
    const history = auditTimeline(relevant, "EVIDENCE_REVIEW", row.id,
      run.organizationId, row.revision,
      ["assetEvidence.review.created", "assetEvidence.review.revised"]);
    issues.push(...history.issues);
    const assessment = inspectEvidenceReview({
      organizationId: run.organizationId, runId: run.id,
      runRevision: run.revision,
    }, step, row, input.checkedAt);
    if (!evidenceMatches)
      issues.push(issue("REVIEW_DIGEST_INVALID", "EVIDENCE_REVIEW",
        row.id));
    if (!assessment.reviewerIsIndependent)
      issues.push(issue("SELF_REVIEW", "EVIDENCE_REVIEW", row.id));
    if (!step || step.status !== "EVIDENCE_RECORDED")
      issues.push(issue("REVIEW_WITHOUT_EVIDENCE", "STEP", row.id));
    if (row.reviewState === "DISPUTED")
      issues.push(issue("REVIEW_DISPUTED", "EVIDENCE_REVIEW", row.id));
    if (row.reviewState === "STALE_REFERENCE" || !evidenceMatches)
      issues.push(issue("REVIEW_STALE", "EVIDENCE_REVIEW", row.id));
    const last = history.events.at(-1);
    if (last && last.actorUserId !== row.reviewerUserId)
      issues.push(issue("ACTOR_MISMATCH", "EVIDENCE_REVIEW", row.id,
        last.id));
    if (last && last.sourceDigest !== null &&
        !eq(last.sourceDigest, row.evidenceDigest))
      issues.push(issue("REVIEW_AUDIT_MISMATCH", "EVIDENCE_REVIEW",
        row.id, last.id));
    if (relevant.length < row.revision)
      issues.push(issue("REVIEW_AUDIT_MISSING", "EVIDENCE_REVIEW",
        row.id));
    if (!history.complete)
      issues.push(issue("REVIEW_REVISION_GAP", "EVIDENCE_REVIEW",
        row.id));
    verifiedReviews.push({
      id: row.id, stepCode: row.stepCode, state: row.reviewState,
      revision: row.revision, sourceRunRevision: row.sourceRunRevision,
      reviewerUserId: row.reviewerUserId,
      originalOperatorUserId: row.originalOperatorUserId,
      currentReferenceMatches: evidenceMatches,
      independentlyReviewed: assessment.sourceVerified &&
        history.complete && scoped,
      auditEvents: relevant.length,
      issueCodes: issues.filter(i => i.resourceId === row.id)
        .map(i => i.code),
    });
  }
  const previous = timeline.events.at(-1);
  if (previous && previous.to !== null && previous.to !== run.state)
    issues.push(issue("STATE_MISMATCH", "RUN", run.id, previous.id));
  if (previous && previous.dossierDigest !== null &&
      !eq(previous.dossierDigest, run.dossierDigest))
    issues.push(issue("SOURCE_DIGEST_MISMATCH", "RUN",
      run.id, previous.id));
  if (run.state === "EVIDENCE_CAPTURED" &&
      (steps.completed !== OPERATOR_STEP_CODES.length ||
       !run.submittedAt || !run.submittedByUserId))
    issues.push(issue("TERMINAL_WITHOUT_SUBMISSION", "RUN", run.id));
  const reviewSummary = summarizeIndependentReviews({
    organizationId: run.organizationId,
    runId: run.id, revision: run.revision, state: run.state,
    steps: steps.items, reviews,
  }, input.checkedAt);
  const independentlyReviewedSteps = verifiedReviews.filter(
    r => r.independentlyReviewed).length;
  const runAuditComplete = timeline.complete &&
    input.runTotal === runEvents.length;
  const reviewAuditComplete = reviews.every(r => {
    const found = verifiedReviews.find(x => x.id === r.id);
    return found?.auditEvents === r.revision &&
      !found.issueCodes.includes("REVIEW_REVISION_GAP");
  }) && input.reviewTotal === reviewEvents.length;
  const reviewReferencesCurrent = verifiedReviews.every(r =>
    r.currentReferenceMatches);
  const evidenceReviewsComplete = reviewSummary.readyForHumanSignoff &&
    independentlyReviewedSteps === OPERATOR_STEP_CODES.length;
  const blockers = issues.filter(x => x.severity === "BLOCK").length;
  const warnings = issues.filter(x => x.severity === "REVIEW").length;
  const canonical = {
    schema: "cyberpilot.assets.acceptance.audit.reconciliation.v1" as const,
    organizationId: run.organizationId, runId: run.id,
    checkedAt: input.checkedAt.toISOString(),
    state: run.state, revision: run.revision,
    sourceDigest: run.sourceDigest, dossierDigest: run.dossierDigest,
    totalRunEvents: input.runTotal,
    totalReviewEvents: input.reviewTotal,
    runAuditComplete, reviewAuditComplete,
    runStateConsistent: !issues.some(x =>
      x.code === "STATE_MISMATCH" ||
      x.code === "TERMINAL_WITHOUT_SUBMISSION"),
    reviewReferencesCurrent, evidenceReviewsComplete,
    evidenceIndependenceComplete:
      verifiedReviews.every(r =>
        r.reviewerUserId !== r.originalOperatorUserId),
    independentlyReviewedSteps,
    recordedSteps: steps.completed,
    reviewCount: reviews.length,
    events: [...timeline.events,
      ...reviewEvents.map(normalizeEvent)],
    reviews: verifiedReviews,
    issues, blockers, warnings,
    localAuditIntegrityVerified: blockers === 0 &&
      runAuditComplete && reviewAuditComplete &&
      reviewReferencesCurrent && initial.valid,
    readyForIndependentHumanDecision:
      blockers === 0 && runAuditComplete &&
      reviewAuditComplete && evidenceReviewsComplete &&
      run.state === "EVIDENCE_CAPTURED",
    externallySigned: false as const,
    legallyApproved: false as const,
    backupsErased: false as const,
    providerLiveChecked: false as const,
    phaseClosed: false as const,
    mergeAuthorized: false as const,
    noDatabaseWrites: true as const,
  };
  return { ...canonical, digest: sha(canonical), limitations: limits };
}
export function verifyAuditReconciliation(report: AuditReconciliationReport) {
  const { digest, limitations, ...canonical } = report;
  const issues: string[] = [];
  if (!eq(digest, sha(canonical)))
    issues.push("Reconciliation report fingerprint mismatch.");
  if (report.blockers !== report.issues.filter(i =>
    i.severity === "BLOCK").length)
    issues.push("Reported blockers do not match issue register.");
  if (report.warnings !== report.issues.filter(i =>
    i.severity === "REVIEW").length)
    issues.push("Reported reviews do not match issue register.");
  if (report.localAuditIntegrityVerified &&
      (!report.runAuditComplete || !report.reviewAuditComplete ||
       report.blockers > 0))
    issues.push("Local audit validity claims contradict blocking events.");
  if (report.readyForIndependentHumanDecision &&
      (!report.evidenceReviewsComplete ||
       !report.localAuditIntegrityVerified ||
       report.state !== "EVIDENCE_CAPTURED"))
    issues.push("Human review eligibility contradicts evidence.");
  if (report.externallySigned || report.legallyApproved ||
      report.backupsErased || report.providerLiveChecked ||
      report.phaseClosed || report.mergeAuthorized ||
      !report.noDatabaseWrites)
    issues.push("Report claims unsupported external action.");
  if (!Array.isArray(limitations) || limitations.length < 5)
    issues.push("Audit caveats were removed.");
  return { valid: issues.length === 0, issues };
}
export function auditReconciliationPlaybook(
  report: AuditReconciliationReport,
) {
  return report.issues.map((i, order) => ({
    order: order + 1,
    code: i.code, severity: i.severity,
    entity: i.entity, resourceId: i.resourceId,
    action: i.nextAction,
    noAutomaticRepair: true as const,
    requiresAuthenticatedHumanInvestigation: true as const,
  }));
}
export function auditReconciliationManifest(
  report: AuditReconciliationReport,
) {
  if (!verifyAuditReconciliation(report).valid)
    fail("CONFLICT", "Cannot export an altered audit report.");
  return {
    schema: "cyberpilot.assets.audit.reconciliation.manifest.v1" as const,
    organizationId: report.organizationId, runId: report.runId,
    checkedAt: report.checkedAt,
    reportDigest: report.digest,
    sourceDigest: report.sourceDigest,
    dossierDigest: report.dossierDigest,
    auditedRunRevisions: report.revision,
    auditedEvidenceReviews: report.reviewCount,
    auditIntegrity: report.localAuditIntegrityVerified,
    outstandingCodes: report.issues.map(i => i.code),
    externalSignatureVerified: false as const,
    phaseMergeAuthorized: false as const,
    databaseWrites: 0 as const,
  };
}
export async function inspectAcceptanceAuditReconciliation(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Acceptance audit reconciliation requires ADMIN or OWNER.");
  const options = parseReconciliationOptions(raw);
  const run = await db.assetOfflineAcceptanceRun.findFirst({
    where: { id: options.runId,
      organizationId: scope.organizationId },
  });
  if (!run) fail("MISSING", "Acceptance run not found in this tenant.");
  const reviews = await db.assetEvidenceReview.findMany({
    where: { organizationId: scope.organizationId,
      acceptanceRunId: run.id },
    orderBy: [{ stepCode: "asc" }],
    take: OPERATOR_STEP_CODES.length + 1,
  });
  if (reviews.length > OPERATOR_STEP_CODES.length)
    fail("CONFLICT", "Independent review register exceeds nine steps.");
  const runWhere = {
    organizationId: scope.organizationId,
    resourceType: "AssetOfflineAcceptanceRun",
    resourceId: run.id,
  };
  const reviewWhere = {
    organizationId: scope.organizationId,
    resourceType: "AssetEvidenceReview",
    resourceId: { in: reviews.map(r => r.id) },
  };
  const [runTotal, reviewTotal] = await Promise.all([
    db.auditEvent.count({ where: runWhere }),
    db.auditEvent.count({ where: reviewWhere }),
  ]);
  if (runTotal > options.maximumRunEvents ||
      reviewTotal > options.maximumReviewEvents)
    fail("CONFLICT", "Audit history exceeds a bounded full inspection.");
  const [runEvents, reviewEvents] = await Promise.all([
    db.auditEvent.findMany({
      where: runWhere,
      orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
      take: options.maximumRunEvents + 1,
    }),
    db.auditEvent.findMany({
      where: reviewWhere,
      orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
      take: options.maximumReviewEvents + 1,
    }),
  ]);
  if (runEvents.length !== runTotal ||
      reviewEvents.length !== reviewTotal)
    fail("CONFLICT", "Audit event count changed during inspection.");
  const result = reconstructAcceptanceAudit({
    run, reviews, runEvents, reviewEvents,
    runTotal, reviewTotal, checkedAt: now,
  });
  if (!verifyAuditReconciliation(result).valid)
    fail("CONFLICT", "Generated reconciliation fingerprint is invalid.");
  return result;
}
