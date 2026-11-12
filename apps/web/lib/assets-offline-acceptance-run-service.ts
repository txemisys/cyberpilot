import { createHash, timingSafeEqual } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { AssetScope } from "./assets-inventory-service";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import { inspectOfflineCloseoutDossier,
  verifyCloseoutDossier } from "./assets-offline-closeout-dossier";

export type OperatorStepCode =
  "CSV_IMPORT_REVIEW" | "SCOPE_AND_PROVENANCE" |
  "STORED_OSV_REVIEW" | "HUMAN_ADVICE_CASES" |
  "ACCEPTANCE_GATES" | "PRIVACY_AND_PII" |
  "RETENTION_BACKUP_OWNER" | "RELEASE_AUDIT_REVIEW" |
  "FINAL_OPERATOR_WALKTHROUGH";
export type OperatorStepStatus =
  "TODO" | "EVIDENCE_RECORDED" | "BLOCKED";
export type OperatorRunStatus =
  "DRAFT" | "IN_PROGRESS" | "BLOCKED" |
  "EVIDENCE_CAPTURED" | "REOPENED";
export type OperatorStep = {
  code: OperatorStepCode;
  status: OperatorStepStatus;
  description: string;
  instructions: string;
  evidenceId: string | null;
  evidenceDescription: string | null;
  recordedByUserId: string | null;
  recordedAt: string | null;
  reason: string | null;
  limitations: string[];
  attestationScope: "LOCAL_OPERATOR_DECLARATION_ONLY";
};
export type OperatorRunCreate = {
  importId: string;
  inspectionId: string;
  idempotencyKey: string;
  bindings: unknown;
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
  reason: string;
};
export type OperatorRunChange = {
  runId: string;
  expectedRevision: number;
  expectedDossierDigest: string;
  operation: "START" | "RECORD_EVIDENCE" | "BLOCK_STEP" |
    "RESET_STEP" | "SUBMIT_FOR_INDEPENDENT_REVIEW" | "REOPEN";
  stepCode: OperatorStepCode | null;
  evidenceId: string | null;
  evidenceDescription: string | null;
  reason: string;
  limitations: string[];
  acknowledgements: string[];
  bindings: unknown;
  acceptancePolicy: unknown;
  privacyPolicy: unknown;
};
export type OperatorRunQuery = {
  offset: number;
  limit: number;
  importId: string | null;
  inspectionId: string | null;
  state: OperatorRunStatus | null;
};
export type OperatorRunCheck = {
  valid: boolean;
  stateCoherent: boolean;
  countsCoherent: boolean;
  evidenceCoherent: boolean;
  idsUnique: boolean;
  noApprovalClaim: true;
  issues: string[];
};
export type OperatorRunReadiness = {
  canSubmitForIndependentReview: boolean;
  completed: number;
  blocked: number;
  outstanding: OperatorStepCode[];
  sourceDossierValid: boolean;
  sourceDigestMatches: boolean;
  explicitHumanSignoffStillRequired: true;
  externalPrivacySignoffStillRequired: true;
  backupDispositionStillRequiresVerification: true;
  mergeAuthorizationGranted: false;
  liveProviderValidated: false;
};
const definitions: Array<{
  code: OperatorStepCode; description: string; instructions: string;
}> = [
  {
    code: "CSV_IMPORT_REVIEW",
    description: "Inspect original customer-declared CSV and persisted import",
    instructions: "Check its original source, size limits, malformed rows, retained fields, observed timestamps and source digest.",
  },
  {
    code: "SCOPE_AND_PROVENANCE",
    description: "Confirm actual inventory coverage and scope exclusions",
    instructions: "Document which endpoints and assets the customer declared and which remain unknown; confirm multitenant boundaries.",
  },
  {
    code: "STORED_OSV_REVIEW",
    description: "Inspect provider observation scope and timestamp",
    instructions: "Check every stored OSV query, exact version binding, incomplete or withdrawn sources and provider-only advisories.",
  },
  {
    code: "HUMAN_ADVICE_CASES",
    description: "Review candidate action cases and operator checklists",
    instructions: "Check positive candidates, revisioned human cases, audit lineage, open tasks, rationales and remediation caveats.",
  },
  {
    code: "ACCEPTANCE_GATES",
    description: "Inspect offline acceptance report and reference regression suite",
    instructions: "Reconcile every mandatory acceptance gate and all thirteen synthetic regression scenarios without inferring LIVE.",
  },
  {
    code: "PRIVACY_AND_PII",
    description: "Review privacy, hostname, pseudonymous owner and audit data",
    instructions: "Document a responsible privacy contact, retention purpose, PII classifications and outstanding approval requirements.",
  },
  {
    code: "RETENTION_BACKUP_OWNER",
    description: "Identify retention, backup and export lifecycle owner",
    instructions: "Review retention exceptions, minimum windows, purge dependencies, export copies, restore tests and backup expiry procedures.",
  },
  {
    code: "RELEASE_AUDIT_REVIEW",
    description: "Reconstruct release decisions and independent audit history",
    instructions: "Verify operator decisions, digest continuity, CAS revision gaps, event actors, release caveats and audit completeness.",
  },
  {
    code: "FINAL_OPERATOR_WALKTHROUGH",
    description: "Perform witnessed offline end-to-end walkthrough",
    instructions: "Execute a representative customer CSV-to-action workflow with a real human witness and retain a referenced record.",
  },
];
export const OPERATOR_STEP_CODES: OperatorStepCode[] =
  definitions.map(d => d.code);
const operations: OperatorRunChange["operation"][] = [
  "START", "RECORD_EVIDENCE", "BLOCK_STEP", "RESET_STEP",
  "SUBMIT_FOR_INDEPENDENT_REVIEW", "REOPEN",
];
const states: OperatorRunStatus[] = [
  "DRAFT", "IN_PROGRESS", "BLOCKED",
  "EVIDENCE_CAPTURED", "REOPENED",
];
const warnings = [
  "Operator evidence references are human declarations until independently checked.",
  "EVIDENCE_CAPTURED does not mean external privacy/legal approval or a final product signoff.",
  "The checklist cannot automatically close Phase 4, remove Draft or authorize a GitHub merge.",
  "A green synthetic scenario suite cannot substitute for a witnessed customer workflow.",
  "A restored backup test does not prove all backups or exports were erased.",
  "The run neither calls OSV providers nor changes findings, scores, quotas or dispatchers.",
];
type DbRun = {
  id: string; organizationId: string;
  importId: string; inspectionId: string;
  idempotencyKey: string; dossierDigest: string; sourceDigest: string;
  state: string; revision: number;
  operatorUserId: string; openingReason: string;
  steps: unknown; limitations: unknown; humanAcknowledgements: unknown;
  completedSteps: number; blockedSteps: number;
  startedAt: Date; updatedAt: Date;
  submittedAt: Date | null; submittedByUserId: string | null;
  submittedReason: string | null;
};
function fail(code: "INVALID" | "FORBIDDEN" | "MISSING" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function obj(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("INVALID", "Operator run command must be a JSON object.");
  return value as Record<string, unknown>;
}
function allowed(input: Record<string, unknown>, names: string[]) {
  if (Object.keys(input).some(key => !names.includes(key)))
    fail("INVALID", "Unexpected operator run request field.");
}
function identifier(value: unknown, name: string) {
  if (typeof value !== "string" ||
      !/^[a-zA-Z0-9_-]{5,150}$/.test(value))
    fail("INVALID", "Invalid operator run " + name + ".");
  return value;
}
function explanation(value: unknown) {
  if (typeof value !== "string" || value.trim().length < 20 ||
      value.length > 1500 || /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "Meaningful operator reason of 20–1500 characters required.");
  return value.trim();
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function digest(value: unknown) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value))
    fail("INVALID", "Expected a valid SHA-256 dossier digest.");
  return value;
}
function equal(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function revision(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > 2147483647)
    fail("INVALID", "Expected operator run CAS revision must be positive.");
  return value;
}
function text(value: unknown, name: string) {
  if (typeof value !== "string" ||
      value.trim().length < 8 || value.length > 800 ||
      /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "Invalid " + name + " reference.");
  return value.trim();
}
function explanations(value: unknown, max = 20) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(v => typeof v !== "string" || v.length < 8 ||
        v.length > 250 || /[\u0000-\u001f\u007f]/.test(v)) ||
      new Set(value).size !== value.length)
    fail("INVALID", "Invalid or duplicated operator run limitations.");
  return value as string[];
}
function acknowledgements(value: unknown) {
  const recognized = [
    "OFFLINE_ONLY", "SOURCE_NOT_EXHAUSTIVE",
    "NOT_LEGAL_SIGNOFF", "BACKUPS_NOT_ERASED",
    "NO_VERIFIED_REMEDIATION",
    "EXTERNAL_PROVIDER_NOT_VALIDATED",
    "INDEPENDENT_HUMAN_DECISION_REQUIRED",
  ];
  if (!Array.isArray(value) || value.length > recognized.length ||
      value.some(v => !recognized.includes(String(v))) ||
      new Set(value).size !== value.length)
    fail("INVALID", "Invalid human scope acknowledgement.");
  return value as string[];
}
function bindings(value: unknown) {
  if (!Array.isArray(value) || value.length > 2000)
    fail("INVALID", "Explicit bounded package mappings required.");
  return value;
}
function manager(scope: AssetScope) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Only ADMIN or OWNER can record closeout walkthroughs.");
}
export function parseOperatorRunCreate(raw: unknown): OperatorRunCreate {
  const v = obj(raw);
  allowed(v, ["importId", "inspectionId", "idempotencyKey",
    "bindings", "acceptancePolicy", "privacyPolicy", "reason"]);
  return {
    importId: identifier(v.importId, "import"),
    inspectionId: identifier(v.inspectionId, "inspection"),
    idempotencyKey: identifier(v.idempotencyKey, "idempotency key"),
    bindings: bindings(v.bindings),
    acceptancePolicy: v.acceptancePolicy ?? {},
    privacyPolicy: v.privacyPolicy ?? {},
    reason: explanation(v.reason),
  };
}
export function parseOperatorRunChange(raw: unknown): OperatorRunChange {
  const v = obj(raw);
  allowed(v, ["runId", "expectedRevision", "expectedDossierDigest",
    "operation", "stepCode", "evidenceId", "evidenceDescription",
    "reason", "limitations", "acknowledgements",
    "bindings", "acceptancePolicy", "privacyPolicy"]);
  if (!operations.includes(v.operation as OperatorRunChange["operation"]))
    fail("INVALID", "Unsupported operator run operation.");
  const stepCode = v.stepCode == null ? null :
    (v.stepCode as OperatorStepCode);
  if (stepCode !== null && !OPERATOR_STEP_CODES.includes(stepCode))
    fail("INVALID", "Unknown offline acceptance checklist step.");
  return {
    runId: identifier(v.runId, "ID"),
    expectedRevision: revision(v.expectedRevision),
    expectedDossierDigest: digest(v.expectedDossierDigest),
    operation: v.operation as OperatorRunChange["operation"],
    stepCode,
    evidenceId: v.evidenceId == null ? null :
      text(v.evidenceId, "evidence ID"),
    evidenceDescription: v.evidenceDescription == null ? null :
      text(v.evidenceDescription, "evidence description"),
    reason: explanation(v.reason),
    limitations: explanations(v.limitations ?? []),
    acknowledgements: acknowledgements(v.acknowledgements ?? []),
    bindings: bindings(v.bindings),
    acceptancePolicy: v.acceptancePolicy ?? {},
    privacyPolicy: v.privacyPolicy ?? {},
  };
}
export function parseOperatorRunQuery(raw: unknown = {}): OperatorRunQuery {
  const v = obj(raw);
  allowed(v, ["offset", "limit", "importId", "inspectionId", "state"]);
  const offset = v.offset ?? 0;
  const limit = v.limit ?? 25;
  if (typeof offset !== "number" || !Number.isSafeInteger(offset) ||
      offset < 0 || offset > 100000 ||
      typeof limit !== "number" || !Number.isSafeInteger(limit) ||
      limit < 1 || limit > 100)
    fail("INVALID", "Invalid operator run page.");
  if (v.state != null && !states.includes(v.state as OperatorRunStatus))
    fail("INVALID", "Unsupported operator run state.");
  return {
    offset, limit,
    importId: v.importId == null ? null : identifier(v.importId, "import"),
    inspectionId: v.inspectionId == null ? null :
      identifier(v.inspectionId, "inspection"),
    state: v.state == null ? null : v.state as OperatorRunStatus,
  };
}
export function initialOperatorSteps(): OperatorStep[] {
  return definitions.map(d => ({
    ...d, status: "TODO", evidenceId: null,
    evidenceDescription: null, recordedByUserId: null,
    recordedAt: null, reason: null, limitations: [],
    attestationScope: "LOCAL_OPERATOR_DECLARATION_ONLY" as const,
  }));
}
export function verifyOperatorSteps(input: unknown): {
  valid: boolean; items: OperatorStep[];
  issues: string[]; completed: number; blocked: number;
} {
  if (!Array.isArray(input) ||
      input.length !== OPERATOR_STEP_CODES.length)
    return {
      valid: false, items: [], issues: ["Step count differs from the fixed acceptance contract."],
      completed: 0, blocked: 0,
    };
  const items = input as OperatorStep[];
  const issues: string[] = [];
  if (new Set(items.map(step => step?.code)).size !==
      OPERATOR_STEP_CODES.length ||
      !OPERATOR_STEP_CODES.every(code => items.some(item =>
        item?.code === code)))
    issues.push("Required acceptance steps were duplicated or removed.");
  for (const step of items) {
    if (!step || !OPERATOR_STEP_CODES.includes(step.code) ||
        !["TODO", "EVIDENCE_RECORDED", "BLOCKED"].includes(step.status))
      issues.push("Unsupported step code or status.");
    else {
      if (step.attestationScope !== "LOCAL_OPERATOR_DECLARATION_ONLY")
        issues.push("Checklist incorrectly claims independent evidence validation.");
      if (step.status === "EVIDENCE_RECORDED" &&
          (!step.evidenceId || !step.evidenceDescription ||
           !step.recordedAt || !step.recordedByUserId ||
           !step.reason || step.reason.length < 20))
        issues.push("Recorded evidence is missing an actor, description or timestamp.");
      if (step.status === "TODO" &&
          (step.evidenceId || step.recordedAt || step.recordedByUserId))
        issues.push("Unstarted step contains undocumented evidence.");
      if (!Array.isArray(step.limitations) ||
          step.limitations.length > 20)
        issues.push("Malformed step limitation record.");
    }
  }
  return {
    valid: issues.length === 0, items, issues,
    completed: items.filter(x => x.status === "EVIDENCE_RECORDED").length,
    blocked: items.filter(x => x.status === "BLOCKED").length,
  };
}
export function verifyOperatorRun(row: DbRun): OperatorRunCheck {
  const steps = verifyOperatorSteps(row.steps);
  const idsUnique = steps.valid &&
    new Set(steps.items.filter(s => s.evidenceId)
      .map(s => s.evidenceId)).size ===
      steps.items.filter(s => s.evidenceId).length;
  const countsCoherent = steps.completed === row.completedSteps &&
    steps.blocked === row.blockedSteps &&
    steps.completed + steps.blocked <= OPERATOR_STEP_CODES.length;
  const stateConsistent = states.includes(row.state as OperatorRunStatus) &&
    row.revision >= 1 &&
    (row.state !== "EVIDENCE_CAPTURED" ||
      (steps.completed === OPERATOR_STEP_CODES.length &&
       steps.blocked === 0 &&
       row.submittedAt !== null &&
       row.submittedByUserId !== null &&
       row.submittedReason !== null));
  const evidenceCoherent = equal(row.dossierDigest, row.dossierDigest) &&
    equal(row.sourceDigest, row.sourceDigest) &&
    row.operatorUserId.length >= 5 &&
    row.openingReason.length >= 20;
  const issues = [
    ...steps.issues,
    ...(!idsUnique ? ["Duplicate evidence reference across checklist steps."] : []),
    ...(!countsCoherent ? ["Stored progress counters differ from checklist."] : []),
    ...(!stateConsistent ? ["Operator run state is inconsistent with evidence."] : []),
    ...(!evidenceCoherent ? ["Run source provenance or actor is invalid."] : []),
  ];
  return {
    valid: issues.length === 0,
    stateCoherent: stateConsistent,
    countsCoherent, evidenceCoherent, idsUnique,
    noApprovalClaim: true, issues,
  };
}
export function operatorRunReadiness(
  steps: OperatorStep[],
  dossierValid: boolean,
  sourceDigestMatches: boolean,
): OperatorRunReadiness {
  const checked = verifyOperatorSteps(steps);
  const outstanding = steps.filter(step =>
    step.status !== "EVIDENCE_RECORDED").map(step => step.code);
  return {
    canSubmitForIndependentReview: checked.valid &&
      checked.completed === OPERATOR_STEP_CODES.length &&
      checked.blocked === 0 &&
      dossierValid && sourceDigestMatches,
    completed: checked.completed,
    blocked: checked.blocked,
    outstanding,
    sourceDossierValid: dossierValid,
    sourceDigestMatches,
    explicitHumanSignoffStillRequired: true,
    externalPrivacySignoffStillRequired: true,
    backupDispositionStillRequiresVerification: true,
    mergeAuthorizationGranted: false,
    liveProviderValidated: false,
  };
}
export function applyOperatorStep(
  steps: OperatorStep[], command: OperatorRunChange,
  userId: string, now: Date,
): OperatorStep[] {
  if (!Number.isFinite(now.getTime()))
    fail("INVALID", "Invalid acceptance walkthrough clock.");
  const existing = verifyOperatorSteps(steps);
  if (!existing.valid)
    fail("CONFLICT", "Stored checklist failed structural verification.");
  const operationsThatNeedStep: OperatorRunChange["operation"][] = [
    "RECORD_EVIDENCE", "BLOCK_STEP", "RESET_STEP",
  ];
  if (!operationsThatNeedStep.includes(command.operation))
    fail("INVALID", "This operation cannot change a checklist step.");
  if (!command.stepCode)
    fail("INVALID", "Choose an exact checklist step.");
  if (command.operation === "RECORD_EVIDENCE" &&
      (!command.evidenceId || !command.evidenceDescription))
    fail("INVALID", "Recorded evidence requires an ID and description.");
  const result = steps.map(step => step.code === command.stepCode ?
    { ...step } : { ...step });
  const selected = result.find(step => step.code === command.stepCode)!;
  if (command.operation === "RESET_STEP") {
    selected.status = "TODO";
    selected.evidenceId = null;
    selected.evidenceDescription = null;
    selected.recordedAt = null;
    selected.recordedByUserId = null;
    selected.reason = null;
    selected.limitations = [];
  } else {
    selected.status = command.operation === "BLOCK_STEP" ?
      "BLOCKED" : "EVIDENCE_RECORDED";
    selected.evidenceId = command.operation === "BLOCK_STEP"
      ? null : command.evidenceId;
    selected.evidenceDescription = command.operation === "BLOCK_STEP"
      ? null : command.evidenceDescription;
    selected.recordedByUserId = userId;
    selected.recordedAt = now.toISOString();
    selected.reason = command.reason;
    selected.limitations = command.limitations;
  }
  if (!verifyOperatorSteps(result).valid)
    fail("CONFLICT", "Checklist update violates the evidence contract.");
  return result;
}
export function nextOperatorRunState(from: OperatorRunStatus,
  operation: OperatorRunChange["operation"],
  steps: OperatorStep[],
  submitAllowed: boolean,
): OperatorRunStatus | null {
  if (operation === "START")
    return from === "DRAFT" || from === "REOPENED"
      ? "IN_PROGRESS" : null;
  if (operation === "REOPEN")
    return from === "BLOCKED" || from === "EVIDENCE_CAPTURED"
      ? "REOPENED" : null;
  if (operation === "SUBMIT_FOR_INDEPENDENT_REVIEW")
    return from === "IN_PROGRESS" && submitAllowed
      ? "EVIDENCE_CAPTURED" : null;
  if (["RECORD_EVIDENCE", "BLOCK_STEP", "RESET_STEP"].includes(operation) &&
      (from === "IN_PROGRESS" || from === "BLOCKED" ||
       from === "REOPENED"))
    return steps.some(s => s.status === "BLOCKED")
      ? "BLOCKED" : "IN_PROGRESS";
  return null;
}
function view(row: DbRun) {
  const verification = verifyOperatorRun(row);
  const steps = verifyOperatorSteps(row.steps).items;
  return {
    ...row, steps,
    verification,
    readiness: operatorRunReadiness(steps,
      verification.valid, true),
    startedAt: row.startedAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    submittedAt: row.submittedAt?.toISOString() ?? null,
    caveats: warnings,
    actualApprovalGranted: false as const,
    legalApprovalGranted: false as const,
    externalTenantValidated: false as const,
  };
}
export async function listOperatorAcceptanceRuns(
  scope: AssetScope, raw: unknown = {},
) {
  manager(scope);
  const query = parseOperatorRunQuery(raw);
  const where = {
    organizationId: scope.organizationId,
    ...(query.importId ? { importId: query.importId } : {}),
    ...(query.inspectionId ? { inspectionId: query.inspectionId } : {}),
    ...(query.state ? { state: query.state } : {}),
  };
  const [total, rows] = await Promise.all([
    db.assetOfflineAcceptanceRun.count({ where }),
    db.assetOfflineAcceptanceRun.findMany({
      where, orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
    }),
  ]);
  return {
    schema: "cyberpilot.assets.operator.acceptance.list.v1" as const,
    total, offset: query.offset, limit: query.limit,
    runs: rows.map(view),
  };
}
async function sourceDossier(scope: AssetScope,
  command: Pick<OperatorRunCreate, "importId" | "inspectionId" |
    "bindings" | "acceptancePolicy" | "privacyPolicy">, now: Date) {
  const dossier = await inspectOfflineCloseoutDossier(scope, {
    importId: command.importId, inspectionId: command.inspectionId,
    bindings: command.bindings,
    acceptancePolicy: command.acceptancePolicy,
    privacyPolicy: command.privacyPolicy,
    maxAuditEvents: 250,
  }, now);
  if (!verifyCloseoutDossier(dossier).valid)
    fail("CONFLICT", "Source dossier failed independent validation.");
  return dossier;
}
export function stableSourceIdentity(dossier: Awaited<ReturnType<typeof sourceDossier>>,
  command: Pick<OperatorRunCreate, "acceptancePolicy" | "privacyPolicy">) {
  // Dossier digests contain timestamps. Stable identity intentionally uses
  // source snapshots and the explicitly selected policy inputs instead.
  return sha({
    schema: "cyberpilot.assets.operator.run.source.identity.v1",
    organizationId: dossier.organizationId,
    importId: dossier.importId,
    inspectionId: dossier.inspectionId,
    inventoryDigest: dossier.inventory.inventoryDigest,
    inspectionDigest: dossier.inventory.inspectionDigest,
    acceptancePolicy: command.acceptancePolicy,
    privacyPolicy: command.privacyPolicy,
  });
}
export async function createOperatorAcceptanceRun(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  manager(scope);
  const command = parseOperatorRunCreate(raw);
  const dossier = await sourceDossier(scope, command, now);
  const identity = stableSourceIdentity(dossier, command);
  const where = { organizationId: scope.organizationId,
    idempotencyKey: command.idempotencyKey };
  const existing = await db.assetOfflineAcceptanceRun.findUnique({
    where: { organizationId_idempotencyKey: where },
  });
  if (existing) {
    if (existing.importId !== command.importId ||
        existing.inspectionId !== command.inspectionId ||
        !equal(existing.sourceDigest, identity))
      fail("CONFLICT", "Idempotency key already belongs to different source evidence.");
    return { replayed: true, run: view(existing) };
  }
  try {
    const created = await db.$transaction(async tx => {
      const row = await tx.assetOfflineAcceptanceRun.create({
        data: {
          organizationId: scope.organizationId,
          importId: command.importId, inspectionId: command.inspectionId,
          idempotencyKey: command.idempotencyKey,
          dossierDigest: dossier.digest,
          sourceDigest: identity,
          state: "DRAFT", revision: 1,
          operatorUserId: scope.userId, openingReason: command.reason,
          steps: JSON.parse(JSON.stringify(initialOperatorSteps())),
          limitations: [],
          humanAcknowledgements: [],
          completedSteps: 0, blockedSteps: 0,
          startedAt: now,
        },
      });
      await tx.auditEvent.create({ data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assetAcceptance.run.created",
        resourceType: "AssetOfflineAcceptanceRun",
        resourceId: row.id,
        metadata: {
          schema: "cyberpilot.assets.operator.acceptance.audit.v1",
          importId: command.importId, inspectionId: command.inspectionId,
          dossierDigest: dossier.digest, sourceDigest: identity,
          revision: 1, state: "DRAFT", reason: command.reason,
          signedOff: false, mergeAuthorized: false,
        },
      } });
      return row;
    });
    return { replayed: false, run: view(created),
      currentBlockers: dossier.counts.blocked };
  } catch (cause) {
    const row = await db.assetOfflineAcceptanceRun.findUnique({
      where: { organizationId_idempotencyKey: where },
    });
    if (row && row.importId === command.importId &&
        row.inspectionId === command.inspectionId &&
        equal(row.sourceDigest, identity))
      return { replayed: true, run: view(row) };
    if (row)
      fail("CONFLICT", "Concurrent run uses different source evidence.");
    throw cause;
  }
}
export async function changeOperatorAcceptanceRun(
  scope: AssetScope, raw: unknown, now = new Date(),
) {
  manager(scope);
  const command = parseOperatorRunChange(raw);
  const current = await db.assetOfflineAcceptanceRun.findFirst({
    where: { id: command.runId, organizationId: scope.organizationId },
  });
  if (!current)
    fail("MISSING", "Run not found in this organization.");
  const check = verifyOperatorRun(current);
  if (!check.valid)
    fail("CONFLICT", "Persisted run checklist failed integrity checks.");
  if (current.revision !== command.expectedRevision ||
      !equal(current.dossierDigest, command.expectedDossierDigest))
    fail("CONFLICT", "Run revision or dossier evidence digest changed.");
  const dossier = await sourceDossier(scope, {
    importId: current.importId, inspectionId: current.inspectionId,
    bindings: command.bindings,
    acceptancePolicy: command.acceptancePolicy,
    privacyPolicy: command.privacyPolicy,
  }, now);
  // Source identity digest excludes the evaluation timestamp; the full
  // dossier digest includes it and therefore changes on every inspection.
  const identity = stableSourceIdentity(dossier, command);
  const sourceMatches = equal(current.sourceDigest, identity);
  if (!sourceMatches && command.operation !== "REOPEN")
    fail("CONFLICT", "Source evidence changed; reopen before proceeding.");
  const oldSteps = verifyOperatorSteps(current.steps).items;
  const stepOperations: OperatorRunChange["operation"][] = [
    "RECORD_EVIDENCE", "BLOCK_STEP", "RESET_STEP",
  ];
  const steps = stepOperations.includes(command.operation)
    ? applyOperatorStep(oldSteps, command, scope.userId, now)
    : oldSteps;
  const readiness = operatorRunReadiness(
    steps, true, sourceMatches);
  const target = nextOperatorRunState(current.state as OperatorRunStatus,
    command.operation, steps,
    readiness.canSubmitForIndependentReview && dossier.counts.blocked === 0);
  if (!target)
    fail("CONFLICT", "Illegal run transition or incomplete human checklist.");
  const completed = steps.filter(s =>
    s.status === "EVIDENCE_RECORDED").length;
  const blocked = steps.filter(s => s.status === "BLOCKED").length;
  const saved = await db.$transaction(async tx => {
    const result = await tx.assetOfflineAcceptanceRun.updateMany({
      where: {
        id: current.id, organizationId: scope.organizationId,
        revision: command.expectedRevision, state: current.state,
        dossierDigest: current.dossierDigest,
      },
      data: {
        revision: { increment: 1 }, state: target,
        steps: JSON.parse(JSON.stringify(steps)),
        completedSteps: completed, blockedSteps: blocked,
        dossierDigest: dossier.digest,
        sourceDigest: identity,
        limitations: command.limitations,
        humanAcknowledgements: command.acknowledgements,
        submittedAt: target === "EVIDENCE_CAPTURED" ? now : null,
        submittedByUserId: target === "EVIDENCE_CAPTURED"
          ? scope.userId : null,
        submittedReason: target === "EVIDENCE_CAPTURED"
          ? command.reason : null,
      },
    });
    if (result.count !== 1)
      fail("CONFLICT", "Concurrent CAS operator run transition rejected.");
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assetAcceptance.run." + command.operation.toLowerCase(),
      resourceType: "AssetOfflineAcceptanceRun",
      resourceId: current.id,
      metadata: {
        schema: "cyberpilot.assets.operator.acceptance.audit.v1",
        from: current.state, to: target,
        revisionBefore: command.expectedRevision,
        revisionAfter: command.expectedRevision + 1,
        stepCode: command.stepCode,
        evidenceId: command.evidenceId,
        completed, blocked,
        reason: command.reason,
        sourceDigest: identity,
        dossierDigest: dossier.digest,
        signedOff: false,
        mergeAuthorized: false,
        externalProviderValidated: false,
      },
    } });
    return tx.assetOfflineAcceptanceRun.findUniqueOrThrow({
      where: { id: current.id },
    });
  });
  return {
    run: view(saved),
    currentReadiness: readiness,
    sourceBlockers: dossier.counts.blocked,
    externallySignedOff: false as const,
    automaticallyAccepted: false as const,
  };
}
export function operatorAcceptanceManifest(row: DbRun) {
  const verification = verifyOperatorRun(row);
  if (!verification.valid)
    fail("CONFLICT", "Cannot export structurally invalid acceptance run.");
  const steps = verifyOperatorSteps(row.steps).items;
  const canonical = {
    schema: "cyberpilot.assets.operator.acceptance.manifest.v1" as const,
    organizationId: row.organizationId,
    runId: row.id,
    importId: row.importId,
    inspectionId: row.inspectionId,
    state: row.state,
    revision: row.revision,
    dossierDigest: row.dossierDigest,
    sourceDigest: row.sourceDigest,
    steps: steps.map(s => ({
      code: s.code, status: s.status,
      evidenceId: s.evidenceId,
      recordedByUserId: s.recordedByUserId,
      recordedAt: s.recordedAt,
    })),
    completed: row.completedSteps,
    blocked: row.blockedSteps,
    evidenceCaptured: row.state === "EVIDENCE_CAPTURED",
    externalSignoffVerified: false as const,
    legalApprovalVerified: false as const,
    phaseClosed: false as const,
    mergeAuthorized: false as const,
  };
  return {
    ...canonical, digest: sha(canonical),
    warning: "This manifest is local and unauthenticated: named witnesses must approve independently.",
  };
}
export async function inspectOperatorRunStatus(
  scope: AssetScope, runId: string, now = new Date(),
) {
  manager(scope);
  const row = await db.assetOfflineAcceptanceRun.findFirst({
    where: { id: identifier(runId, "ID"),
      organizationId: scope.organizationId },
  });
  if (!row) fail("MISSING", "Operator acceptance run not found.");
  const manifest = operatorAcceptanceManifest(row);
  const audits = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceId: row.id,
      resourceType: "AssetOfflineAcceptanceRun",
    },
    select: { id: true, action: true, actorUserId: true,
      occurredAt: true, metadata: true },
    orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
    take: 200,
  });
  const auditCoverage = audits.length >= row.revision &&
    audits.length < 200 &&
    audits.every(a => a.actorUserId !== null);
  return {
    schema: "cyberpilot.assets.operator.acceptance.status.v1" as const,
    evaluatedAt: now.toISOString(),
    organizationId: scope.organizationId,
    run: view(row), manifest,
    audit: {
      observedCount: audits.length,
      expectedRevision: row.revision,
      completeWithinBound: auditCoverage,
      events: audits.map(a => ({
        id: a.id, action: a.action,
        occurredAt: a.occurredAt.toISOString(),
        actorUserId: a.actorUserId,
      })),
    },
    readyForExternalSignoff: row.state === "EVIDENCE_CAPTURED" &&
      auditCoverage,
    externalSignoffGranted: false as const,
    phaseClosed: false as const,
    warning: warnings,
  };
}
