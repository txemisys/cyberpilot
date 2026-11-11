import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import { inspectAssetPrivacyReadiness } from "./assets-privacy-readiness-service";
import type { PrivacyReadinessReport, PrivacyImportAssessment } from
  "./assets-privacy-readiness";

export type RetentionState = "PENDING" | "IN_REVIEW" |
  "DOCUMENTED_WITH_EXCEPTIONS" | "REJECTED" | "REOPENED";
export type RetentionOperation = "START_REVIEW" | "DOCUMENT_EXCEPTIONS" |
  "REJECT" | "REOPEN";
export type BackupDisposition = "UNVERIFIED" |
  "PROCEDURE_DOCUMENTED" | "REQUIRES_EXTERNAL_VERIFICATION";
export type PersonalDataDisposition = "REQUIRES_REVIEW" |
  "RETENTION_DOCUMENTED" | "EXTERNAL_APPROVAL_REQUIRED";
export type RetentionAcknowledgement =
  "DATA_MINIMIZATION_REVIEWED" | "HOSTNAMES_MAY_BE_PERSONAL" |
  "OWNER_HASH_NOT_ANONYMOUS" | "HISTORIC_EVIDENCE_RETAINED" |
  "BACKUPS_NOT_ERASED" | "LEGAL_APPROVAL_NOT_INFERRED" |
  "CROSS_SYSTEM_EXPORTS_UNVERIFIED";
export const RETENTION_ACKNOWLEDGEMENTS: RetentionAcknowledgement[] = [
  "DATA_MINIMIZATION_REVIEWED", "HOSTNAMES_MAY_BE_PERSONAL",
  "OWNER_HASH_NOT_ANONYMOUS", "HISTORIC_EVIDENCE_RETAINED",
  "BACKUPS_NOT_ERASED", "LEGAL_APPROVAL_NOT_INFERRED",
  "CROSS_SYSTEM_EXPORTS_UNVERIFIED",
];
export type RetentionException = {
  gateId: string;
  reason: string;
  owner: string;
  reviewBy: string;
  externalTicket: string | null;
};
export type RetentionCreate = {
  importId: string;
  policy: unknown;
  reason: string;
  exceptions: RetentionException[];
  acknowledgements: RetentionAcknowledgement[];
  backupDisposition: BackupDisposition;
  personalDataDisposition: PersonalDataDisposition;
  nextReviewAt: string | null;
};
export type RetentionChange = {
  reviewId: string;
  expectedRevision: number;
  expectedPrivacyDigest: string;
  operation: RetentionOperation;
  policy: unknown;
  reason: string;
  exceptions: RetentionException[];
  acknowledgements: RetentionAcknowledgement[];
  backupDisposition: BackupDisposition;
  personalDataDisposition: PersonalDataDisposition;
  nextReviewAt: string | null;
};
export type RetentionQuery = {
  offset: number;
  limit: number;
  importId: string | null;
  state: RetentionState | null;
  dueBefore: string | null;
};
export type RetentionGateAssessment = {
  gateId: string;
  severity: "BLOCK" | "REVIEW";
  rationale: string;
  addressedBy: RetentionException | null;
  status: "UNRESOLVED" | "DOCUMENTED_EXCEPTION";
};
export type RetentionVerification = {
  valid: boolean;
  reportDigestValid: boolean;
  matchingScope: boolean;
  matchingImport: boolean;
  matchingSourceDigest: boolean;
  matchingPolicyDigest: boolean;
  stateConsistent: boolean;
  humanCaveatsPreserved: boolean;
  reasons: string[];
  externalApprovalVerified: false;
  backupErasureVerified: false;
  legalSignoffVerified: false;
};
type DatabaseRow = {
  id: string;
  organizationId: string;
  importId: string;
  state: string;
  revision: number;
  sourceDigest: string;
  privacyDigest: string;
  policyDigest: string;
  assessmentAt: Date;
  snapshot: unknown;
  requestedByUserId: string;
  initialReason: string;
  reviewedByUserId: string | null;
  decisionReason: string | null;
  acknowledgements: unknown;
  exceptions: unknown;
  backupDisposition: string;
  personalDataDisposition: string;
  nextReviewAt: Date | null;
  decidedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};
const states: RetentionState[] = [
  "PENDING", "IN_REVIEW", "DOCUMENTED_WITH_EXCEPTIONS",
  "REJECTED", "REOPENED",
];
const backupStates: BackupDisposition[] = [
  "UNVERIFIED", "PROCEDURE_DOCUMENTED",
  "REQUIRES_EXTERNAL_VERIFICATION",
];
const dataStates: PersonalDataDisposition[] = [
  "REQUIRES_REVIEW", "RETENTION_DOCUMENTED",
  "EXTERNAL_APPROVAL_REQUIRED",
];
const operations: RetentionOperation[] = [
  "START_REVIEW", "DOCUMENT_EXCEPTIONS", "REJECT", "REOPEN",
];
const warnings = [
  "This is an internal administrative record, not a verified legal or privacy approval.",
  "Documenting an exception is not its resolution; outstanding gates remain visible.",
  "A procedure for backups does not mean backups, exports, or restored copies were erased.",
  "A pseudonymous owner hash and identifiable hostname can still represent personal data.",
  "No OSV LIVE provider, external tenant, SecurityFinding, CyberScore or scheduler is modified.",
];
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  reason: string): never {
  throw new WorkInputError(code, reason);
}
function obj(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Retention review expects a JSON object.");
  return value as Record<string, unknown>;
}
function only(input: Record<string, unknown>, keys: string[]) {
  if (Object.keys(input).some(key => !keys.includes(key)))
    fail("INVALID", "Unexpected retention review property.");
}
function identifier(value: unknown, name: string) {
  if (typeof value !== "string" ||
      !/^[a-zA-Z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid retention " + name + ".");
  return value;
}
function reason(value: unknown, maximum = 1500) {
  if (typeof value !== "string" || value.trim().length < 20 ||
      value.length > maximum || /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "Retention review requires a human reason of 20–" +
      maximum + " characters.");
  return value.trim();
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equalsHash(a: unknown, b: unknown) {
  if (typeof a !== "string" || typeof b !== "string" ||
      !/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b))
    return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function hash(value: unknown) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value))
    fail("INVALID", "Expected SHA-256 privacy evidence digest.");
  return value;
}
function revision(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > 2147483647)
    fail("INVALID", "Expected a positive CAS revision.");
  return value;
}
function date(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    fail("INVALID", "Next human review must be an ISO UTC timestamp.");
  return new Date(value).toISOString();
}
function enumValue<T extends string>(value: unknown, entries: readonly T[],
  label: string): T {
  if (typeof value !== "string" || !entries.includes(value as T))
    fail("INVALID", "Unsupported " + label + ".");
  return value as T;
}
function acknowledgements(value: unknown): RetentionAcknowledgement[] {
  if (!Array.isArray(value) || value.length > RETENTION_ACKNOWLEDGEMENTS.length ||
      value.some(item => !RETENTION_ACKNOWLEDGEMENTS.includes(
        item as RetentionAcknowledgement)) ||
      new Set(value).size !== value.length)
    fail("INVALID", "Invalid or duplicated retention acknowledgement.");
  return value as RetentionAcknowledgement[];
}
function exceptions(value: unknown): RetentionException[] {
  if (!Array.isArray(value) || value.length > 60)
    fail("INVALID", "Retention exceptions exceed the bounded list.");
  const result: RetentionException[] = [];
  for (const entry of value) {
    const record = obj(entry);
    only(record, ["gateId", "reason", "owner", "reviewBy", "externalTicket"]);
    const gateId = record.gateId;
    if (typeof gateId !== "string" ||
        !/^[A-Z][A-Z0-9_]{2,79}$/.test(gateId))
      fail("INVALID", "Exception gate must be a bounded identifier.");
    if (typeof record.owner !== "string" ||
        !/^[a-zA-Z0-9_.@ -]{3,120}$/.test(record.owner))
      fail("INVALID", "Exception requires a responsible owner.");
    const reviewBy = date(record.reviewBy);
    if (!reviewBy)
      fail("INVALID", "Exception needs an explicit review-by date.");
    const ticket = record.externalTicket;
    if (ticket != null && (typeof ticket !== "string" ||
        ticket.length < 5 || ticket.length > 200 ||
        /[\u0000-\u001f\u007f]/.test(ticket)))
      fail("INVALID", "Invalid exception reference.");
    result.push({
      gateId, reason: reason(record.reason, 1000),
      owner: record.owner.trim(), reviewBy,
      externalTicket: ticket == null ? null : ticket.trim(),
    });
  }
  if (new Set(result.map(row => row.gateId)).size !== result.length)
    fail("INVALID", "Every retention gate may have only one tracked exception.");
  return result;
}
function reviewCommon(v: Record<string, unknown>) {
  return {
    policy: v.policy ?? {},
    reason: reason(v.reason),
    exceptions: exceptions(v.exceptions ?? []),
    acknowledgements: acknowledgements(v.acknowledgements ?? []),
    backupDisposition: enumValue(v.backupDisposition ?? "UNVERIFIED",
      backupStates, "backup disposition"),
    personalDataDisposition: enumValue(
      v.personalDataDisposition ?? "REQUIRES_REVIEW", dataStates,
      "personal-data disposition"),
    nextReviewAt: date(v.nextReviewAt),
  };
}
export function parseRetentionCreate(raw: unknown): RetentionCreate {
  const v = obj(raw);
  only(v, ["importId", "policy", "reason", "exceptions",
    "acknowledgements", "backupDisposition",
    "personalDataDisposition", "nextReviewAt"]);
  return { importId: identifier(v.importId, "import ID"),
    ...reviewCommon(v) };
}
export function parseRetentionChange(raw: unknown): RetentionChange {
  const v = obj(raw);
  only(v, ["reviewId", "expectedRevision", "expectedPrivacyDigest",
    "operation", "policy", "reason", "exceptions",
    "acknowledgements", "backupDisposition",
    "personalDataDisposition", "nextReviewAt"]);
  return {
    reviewId: identifier(v.reviewId, "review ID"),
    expectedRevision: revision(v.expectedRevision),
    expectedPrivacyDigest: hash(v.expectedPrivacyDigest),
    operation: enumValue(v.operation, operations, "retention decision"),
    ...reviewCommon(v),
  };
}
export function parseRetentionQuery(raw: unknown = {}): RetentionQuery {
  const v = obj(raw);
  only(v, ["offset", "limit", "importId", "state", "dueBefore"]);
  const offset = v.offset ?? 0;
  const limit = v.limit ?? 25;
  if (typeof offset !== "number" || !Number.isSafeInteger(offset) ||
      offset < 0 || offset > 100000 ||
      typeof limit !== "number" || !Number.isSafeInteger(limit) ||
      limit < 1 || limit > 100)
    fail("INVALID", "Invalid retention review pagination.");
  return {
    offset, limit,
    importId: v.importId == null ? null :
      identifier(v.importId, "import ID"),
    state: v.state == null ? null :
      enumValue(v.state, states, "retention state"),
    dueBefore: date(v.dueBefore),
  };
}
export function retentionTarget(from: RetentionState,
  operation: RetentionOperation): RetentionState | null {
  if ((from === "PENDING" || from === "REOPENED") &&
      operation === "START_REVIEW") return "IN_REVIEW";
  if (from === "IN_REVIEW" && operation === "DOCUMENT_EXCEPTIONS")
    return "DOCUMENTED_WITH_EXCEPTIONS";
  if ((from === "PENDING" || from === "IN_REVIEW" ||
       from === "REOPENED") && operation === "REJECT") return "REJECTED";
  if ((from === "REJECTED" || from === "DOCUMENTED_WITH_EXCEPTIONS") &&
      operation === "REOPEN") return "REOPENED";
  return null;
}
export function missingRetentionAcknowledgements(
  value: RetentionAcknowledgement[],
) {
  return RETENTION_ACKNOWLEDGEMENTS.filter(item => !value.includes(item));
}
function reportFromEnvelope(value: unknown): PrivacyReadinessReport | null {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return null;
  const envelope = value as { canonical?: unknown };
  if (typeof envelope.canonical !== "string" ||
      envelope.canonical.length > 2_000_000)
    return null;
  try {
    const result: unknown = JSON.parse(envelope.canonical);
    return result && typeof result === "object" && !Array.isArray(result)
      ? result as PrivacyReadinessReport : null;
  } catch { return null; }
}
function reportEnvelope(report: PrivacyReadinessReport) {
  return { canonical: JSON.stringify(report) };
}
export function verifyRetentionReview(row: DatabaseRow): RetentionVerification {
  const report = reportFromEnvelope(row.snapshot);
  const source = report?.imports.find(item => item.importId === row.importId);
  const validTime = report?.evaluatedAt === row.assessmentAt.toISOString();
  const reportDigestValid = !!report && (() => {
    const { digest: storedDigest, warnings: notes, ...canonical } = report;
    return equalsHash(storedDigest, digest(canonical)) &&
      equalsHash(storedDigest, row.privacyDigest) &&
      Array.isArray(notes) && notes.length >= 1;
  })();
  const matchingScope = report?.organizationId === row.organizationId &&
    report?.fullyExamined === true && validTime;
  const matchingImport = !!source &&
    report?.importedCount === report?.imports.length;
  const matchingSourceDigest = !!source &&
    equalsHash(source.sourceDigest, row.sourceDigest);
  const matchingPolicyDigest = !!report &&
    equalsHash(row.policyDigest, digest(report.policy));
  const final = row.state === "DOCUMENTED_WITH_EXCEPTIONS" ||
    row.state === "REJECTED";
  const stateConsistent = states.includes(row.state as RetentionState) &&
    Number.isSafeInteger(row.revision) && row.revision > 0 &&
    (row.decidedAt !== null) === final &&
    (row.reviewedByUserId !== null) === final &&
    (row.decisionReason === null ||
      row.decisionReason.length >= 20);
  const humanCaveatsPreserved = !!report &&
    report.backupDeletionVerified === false &&
    report.personalDataErased === false &&
    report.userConsentInferred === false &&
    report.readiness.pendingOperatorApproval === true &&
    backupStates.includes(row.backupDisposition as BackupDisposition) &&
    dataStates.includes(row.personalDataDisposition as PersonalDataDisposition);
  const reasons = [
    ...(!reportDigestValid ? ["Retention snapshot SHA-256 mismatch."] : []),
    ...(!matchingScope ? ["Retention tenant or evaluation clock mismatch."] : []),
    ...(!matchingImport ? ["Selected inventory is absent or partial."] : []),
    ...(!matchingSourceDigest ? ["Original import digest mismatch."] : []),
    ...(!matchingPolicyDigest ? ["Policy SHA-256 mismatch."] : []),
    ...(!stateConsistent ? ["Manual retention state is inconsistent."] : []),
    ...(!humanCaveatsPreserved ?
      ["Backup/PII/legal limitations are missing."] : []),
  ];
  return {
    valid: reasons.length === 0, reportDigestValid,
    matchingScope, matchingImport, matchingSourceDigest,
    matchingPolicyDigest, stateConsistent, humanCaveatsPreserved,
    reasons, externalApprovalVerified: false,
    backupErasureVerified: false, legalSignoffVerified: false,
  };
}
export function assessRetentionExceptions(report: PrivacyReadinessReport,
  selected: PrivacyImportAssessment, entries: RetentionException[],
): RetentionGateAssessment[] {
  const selectedGates = report.gates.filter(gate =>
    gate.severity !== "PASS" &&
    (gate.affectedImportIds.length === 0 ||
      gate.affectedImportIds.includes(selected.importId)));
  const known = new Map(selectedGates.map(gate => [gate.id, gate]));
  if (entries.some(entry => !known.has(
    entry.gateId as typeof selectedGates[number]["id"])))
    fail("INVALID", "Exception references a gate not present for the selected import.");
  return selectedGates.map(gate => {
    const match = entries.find(entry => entry.gateId === gate.id) ?? null;
    return {
      gateId: gate.id,
      severity: gate.severity === "BLOCK" ? "BLOCK" : "REVIEW",
      rationale: gate.rationale, addressedBy: match,
      status: match ? "DOCUMENTED_EXCEPTION" : "UNRESOLVED",
    };
  });
}
export function eligibleToDocumentRetention(
  report: PrivacyReadinessReport, selected: PrivacyImportAssessment,
  command: Pick<RetentionCreate, "exceptions" | "acknowledgements" |
    "backupDisposition" | "personalDataDisposition" | "nextReviewAt">,
  now: Date,
) {
  const assessments = assessRetentionExceptions(
    report, selected, command.exceptions);
  const unresolved = assessments.filter(gate =>
    gate.status === "UNRESOLVED");
  const missing = missingRetentionAcknowledgements(
    command.acknowledgements);
  const exceptionExpired = command.exceptions.some(entry =>
    new Date(entry.reviewBy).getTime() <= now.getTime());
  const futureFollowup = !!command.nextReviewAt &&
    new Date(command.nextReviewAt).getTime() > now.getTime();
  const legalCaveat = command.personalDataDisposition ===
    "EXTERNAL_APPROVAL_REQUIRED" ||
    command.personalDataDisposition === "REQUIRES_REVIEW" ||
    command.personalDataDisposition === "RETENTION_DOCUMENTED";
  return {
    eligible: report.fullyExamined && unresolved.length === 0 &&
      missing.length === 0 && !exceptionExpired && futureFollowup &&
      legalCaveat && command.backupDisposition !== "UNVERIFIED",
    unresolved, missing, exceptionExpired, futureFollowup,
    noLegalApprovalImplied: true as const,
    noBackupErasureImplied: true as const,
  };
}
function manager(scope: AssetScope) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Retention decisions require an ADMIN or OWNER.");
}
async function currentEvidence(scope: AssetScope, importId: string,
  policy: unknown, now: Date) {
  const report = await inspectAssetPrivacyReadiness(
    scope, { policy }, now);
  const selected = report.imports.find(row => row.importId === importId);
  if (!selected)
    fail("MISSING", "Selected import is not part of this scoped privacy assessment.");
  if (!report.fullyExamined || report.importedCount !== report.imports.length)
    fail("CONFLICT", "Retention review cannot use a partial organization inventory.");
  if (!/^[a-f0-9]{64}$/.test(selected.sourceDigest))
    fail("CONFLICT", "Selected source digest is incomplete.");
  return { report, selected, policyDigest: digest(report.policy) };
}
function view(row: DatabaseRow) {
  const decoded = reportFromEnvelope(row.snapshot);
  const verification = verifyRetentionReview(row);
  return {
    ...row, assessmentAt: row.assessmentAt.toISOString(),
    nextReviewAt: row.nextReviewAt?.toISOString() ?? null,
    decidedAt: row.decidedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    snapshot: decoded,
    verification,
    caveats: warnings,
  };
}
export async function listAssetRetentionReviews(scope: AssetScope,
  raw: unknown = {}) {
  manager(scope);
  const options = parseRetentionQuery(raw);
  const where = {
    organizationId: scope.organizationId,
    ...(options.importId ? { importId: options.importId } : {}),
    ...(options.state ? { state: options.state } : {}),
    ...(options.dueBefore ? {
      nextReviewAt: { lte: new Date(options.dueBefore) },
    } : {}),
  };
  const [total, rows] = await Promise.all([
    db.assetRetentionReview.count({ where }),
    db.assetRetentionReview.findMany({
      where, orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      skip: options.offset, take: options.limit,
    }),
  ]);
  return {
    schema: "cyberpilot.assets.retention.review.list.v1" as const,
    total, offset: options.offset, limit: options.limit,
    reviews: rows.map(view),
  };
}
export async function createAssetRetentionReview(scope: AssetScope,
  raw: unknown, now = new Date()) {
  manager(scope);
  const command = parseRetentionCreate(raw);
  const evidence = await currentEvidence(
    scope, command.importId, command.policy, now);
  assessRetentionExceptions(
    evidence.report, evidence.selected, command.exceptions);
  const where = {
    organizationId: scope.organizationId, importId: command.importId,
  };
  const existing = await db.assetRetentionReview.findUnique({
    where: { organizationId_importId: where },
  });
  if (existing) {
    if (!equalsHash(existing.sourceDigest, evidence.selected.sourceDigest))
      fail("CONFLICT", "Existing retention review targets different source evidence.");
    return { replayed: true, review: view(existing) };
  }
  try {
    const created = await db.$transaction(async tx => {
      const row = await tx.assetRetentionReview.create({ data: {
        ...where, state: "PENDING", revision: 1,
        sourceDigest: evidence.selected.sourceDigest,
        privacyDigest: evidence.report.digest,
        policyDigest: evidence.policyDigest,
        assessmentAt: now,
        snapshot: reportEnvelope(evidence.report),
        requestedByUserId: scope.userId,
        initialReason: command.reason,
        acknowledgements: command.acknowledgements,
        exceptions: command.exceptions,
        backupDisposition: command.backupDisposition,
        personalDataDisposition: command.personalDataDisposition,
        nextReviewAt: command.nextReviewAt ?
          new Date(command.nextReviewAt) : null,
      } });
      await tx.auditEvent.create({ data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assetRetention.review.created",
        resourceType: "AssetRetentionReview", resourceId: row.id,
        metadata: {
          schema: "cyberpilot.assets.retention.audit.v1",
          importId: command.importId, revision: 1,
          state: "PENDING", sourceDigest: evidence.selected.sourceDigest,
          privacyDigest: evidence.report.digest,
          reason: command.reason, legalApprovalVerified: false,
          backupsErased: false,
        },
      } });
      return row;
    });
    return { replayed: false, review: view(created) };
  } catch (cause) {
    const current = await db.assetRetentionReview.findUnique({
      where: { organizationId_importId: where },
    });
    if (current && equalsHash(current.sourceDigest,
      evidence.selected.sourceDigest))
      return { replayed: true, review: view(current) };
    if (current) fail("CONFLICT", "Concurrent retention review differs.");
    throw cause;
  }
}
export async function transitionAssetRetentionReview(scope: AssetScope,
  raw: unknown, now = new Date()) {
  manager(scope);
  const command = parseRetentionChange(raw);
  const record = await db.assetRetentionReview.findFirst({
    where: { id: command.reviewId, organizationId: scope.organizationId },
  });
  if (!record)
    fail("MISSING", "Retention review is absent from this organization.");
  const verification = verifyRetentionReview(record);
  if (!verification.valid)
    fail("CONFLICT", "Persisted privacy review evidence failed verification.");
  if (record.revision !== command.expectedRevision)
    fail("CONFLICT", "Retention CAS revision changed.");
  if (!equalsHash(record.privacyDigest, command.expectedPrivacyDigest))
    fail("CONFLICT", "Privacy snapshot no longer matches the selected evidence.");
  const target = retentionTarget(
    record.state as RetentionState, command.operation);
  if (!target)
    fail("CONFLICT", "Illegal retention state transition.");
  const original = reportFromEnvelope(record.snapshot);
  if (!original)
    fail("CONFLICT", "Stored privacy report could not be decoded.");
  const historical = await currentEvidence(scope, record.importId,
    command.policy, record.assessmentAt);
  if (command.operation !== "REOPEN" &&
      (!equalsHash(record.privacyDigest, historical.report.digest) ||
       !equalsHash(record.sourceDigest, historical.selected.sourceDigest) ||
       !equalsHash(record.policyDigest, historical.policyDigest)))
    fail("CONFLICT", "Historical retention evidence changed; reopen first.");
  const evidence = await currentEvidence(
    scope, record.importId, command.policy, now);
  const gate = eligibleToDocumentRetention(
    evidence.report, evidence.selected, command, now);
  if (command.operation === "DOCUMENT_EXCEPTIONS" && !gate.eligible)
    fail("CONFLICT", "Unresolved privacy gates, acknowledgements or follow-up are missing.");
  if (command.operation !== "REOPEN" &&
      !equalsHash(record.sourceDigest, evidence.selected.sourceDigest))
    fail("CONFLICT", "Inventory digest changed during review.");
  const saved = await db.$transaction(async tx => {
    const result = await tx.assetRetentionReview.updateMany({
      where: {
        id: record.id, organizationId: scope.organizationId,
        revision: command.expectedRevision, state: record.state,
        privacyDigest: record.privacyDigest,
      },
      data: {
        revision: { increment: 1 }, state: target,
        sourceDigest: evidence.selected.sourceDigest,
        privacyDigest: evidence.report.digest,
        policyDigest: evidence.policyDigest,
        assessmentAt: now, snapshot: reportEnvelope(evidence.report),
        exceptions: command.exceptions,
        acknowledgements: command.acknowledgements,
        backupDisposition: command.backupDisposition,
        personalDataDisposition: command.personalDataDisposition,
        nextReviewAt: command.nextReviewAt ?
          new Date(command.nextReviewAt) : null,
        reviewedByUserId: target === "REJECTED" ||
          target === "DOCUMENTED_WITH_EXCEPTIONS"
          ? scope.userId : null,
        decidedAt: target === "REJECTED" ||
          target === "DOCUMENTED_WITH_EXCEPTIONS" ? now : null,
        decisionReason: command.reason,
      },
    });
    if (result.count !== 1)
      fail("CONFLICT", "Concurrent retention review transition rejected.");
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assetRetention.review." + command.operation.toLowerCase(),
      resourceType: "AssetRetentionReview", resourceId: record.id,
      metadata: {
        schema: "cyberpilot.assets.retention.audit.v1",
        previousState: record.state, nextState: target,
        revisionBefore: command.expectedRevision,
        revisionAfter: command.expectedRevision + 1,
        privacyDigest: evidence.report.digest,
        sourceDigest: evidence.selected.sourceDigest,
        reason: command.reason,
        exceptionsCount: command.exceptions.length,
        unresolvedGates: gate.unresolved.map(row => row.gateId),
        acknowledgements: command.acknowledgements,
        backupDisposition: command.backupDisposition,
        personalDataDisposition: command.personalDataDisposition,
        legalApprovalVerified: false, backupsErased: false,
      },
    } });
    return tx.assetRetentionReview.findUniqueOrThrow({
      where: { id: record.id },
    });
  });
  return {
    review: view(saved),
    gateAssessment: gate,
    reviewDocumented: target === "DOCUMENTED_WITH_EXCEPTIONS",
    legalApprovalVerified: false, backupsErased: false,
  };
}
export async function inspectRetentionReviewReadiness(scope: AssetScope,
  raw: unknown, now = new Date()) {
  manager(scope);
  const command = parseRetentionCreate(raw);
  const { report, selected } = await currentEvidence(
    scope, command.importId, command.policy, now);
  return {
    schema: "cyberpilot.assets.retention.review.preview.v1" as const,
    organizationId: scope.organizationId,
    importId: command.importId,
    privacyDigest: report.digest,
    sourceDigest: selected.sourceDigest,
    generatedAt: now.toISOString(),
    selected,
    gates: assessRetentionExceptions(report, selected, command.exceptions),
    permission: eligibleToDocumentRetention(report, selected, command, now),
    privacyReadiness: report.readiness,
    caveats: warnings,
    databaseWrites: 0 as const,
    externalProviderRequests: 0 as const,
    legalSignoffGranted: false as const,
    backupsErased: false as const,
  };
}
