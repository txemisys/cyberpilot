import { db } from "@cyberpilot/database";
import {
  WorkInputError, canManageWork, canReadWork,
} from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  parseAssetAdviceInput, buildAssetAdviceRows,
} from "./assets-action-guidance";
import type { AssetAdviceRow } from "./assets-action-guidance";
import { readAssetAdviceSnapshot } from "./assets-action-guidance-service";

/**
 * Workflow statuses describe operator review only.
 * Neither a finished checklist nor a dismissed case changes vulnerability
 * evidence, SecurityFinding, Remediation, CyberScore or provider quota.
 */
export type CaseStatus = "OPEN" | "IN_REVIEW" |
  "DISMISSED" | "WORK_COMPLETED";
export type StepStatus = "TODO" | "IN_PROGRESS" | "BLOCKED" | "DONE";
export type CaseDecision = "START_REVIEW" | "DISMISS" |
  "COMPLETE_WORK" | "REOPEN";
export type CaseCreate = {
  importId: string;
  inspectionId: string;
  bindings: unknown;
  evidenceFingerprint: string;
  reason: string;
};
export type CaseTransition = {
  caseId: string; expectedRevision: number;
  expectedEvidenceFingerprint: string;
  operation: CaseDecision;
  reason: string;
};
export type StepTransition = {
  caseId: string; actionCode: string;
  expectedCaseRevision: number;
  expectedStepRevision: number;
  status: StepStatus;
  note: string;
};
export type CaseQuery = {
  offset: number; limit: number;
  status: CaseStatus | null;
  importId: string | null;
  inspectionId: string | null;
};
export type CaseRow = {
  id: string; organizationId: string;
  importId: string; inspectionId: string;
  evidenceFingerprint: string;
  inventoryDigest: string; inspectionDigest: string;
  externalId: string; normalizedProductKey: string;
  softwareVersion: string | null;
  status: CaseStatus; category: string;
  priority: string; revision: number;
  title: string;
  rationale: unknown;
  actions: unknown;
  advisoryIds: unknown;
  openedAt: string;
  lastDecisionAt: string | null;
  lastDecisionReason: string | null;
  lastDecisionUserId: string | null;
  steps: Array<{
    id: string; actionCode: string;
    status: StepStatus; revision: number;
    note: string | null;
    completedAt: string | null;
    completedByUserId: string | null;
  }>;
};
const statusOptions: CaseStatus[] = [
  "OPEN", "IN_REVIEW", "DISMISSED", "WORK_COMPLETED",
];
function fail(code: "INVALID" | "MISSING" | "FORBIDDEN" | "CONFLICT",
  message: string): never {
  throw new WorkInputError(code, message);
}
function obj(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    fail("INVALID", "Asset case operation must be an object.");
  return input as Record<string, unknown>;
}
function only(input: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(input).some(x => !allowed.includes(x)))
    fail("INVALID", "Unexpected asset case property.");
}
function label(value: unknown, name: string, maximum: number) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > maximum || /[\u0000-\u001f\u007f]/.test(value))
    fail("INVALID", "Invalid case " + name + ".");
  return value.trim();
}
function identifier(value: unknown, name: string) {
  const result = label(value, name, 150);
  if (!/^[a-zA-Z0-9_-]{5,150}$/.test(result))
    fail("INVALID", "Invalid case " + name + ".");
  return result;
}
function fingerprint(value: unknown) {
  const result = label(value, "evidence fingerprint", 64);
  if (!/^[a-f0-9]{64}$/.test(result))
    fail("INVALID", "Expected a SHA-256 evidence fingerprint.");
  return result;
}
function reason(value: unknown) {
  const text = label(value, "investigation reason", 1000);
  if (text.length < 20)
    fail("INVALID", "Case investigation requires at least 20 characters.");
  return text;
}
function rev(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 1 || value > 2147483647)
    fail("INVALID", "A positive case revision is required.");
  return value;
}
function requireManager(scope: AssetScope) {
  if (!canManageWork(scope.role))
    fail("FORBIDDEN", "Only an administrator may change asset review cases.");
}
export function parseCaseCreate(input: unknown): CaseCreate {
  const v = obj(input);
  only(v, ["importId", "inspectionId", "bindings",
    "evidenceFingerprint", "reason"]);
  if (!Array.isArray(v.bindings))
    fail("INVALID", "Explicit customer package mappings are required.");
  return {
    importId: identifier(v.importId, "inventory ID"),
    inspectionId: identifier(v.inspectionId, "inspection ID"),
    bindings: v.bindings,
    evidenceFingerprint: fingerprint(v.evidenceFingerprint),
    reason: reason(v.reason),
  };
}
export function parseCaseTransition(input: unknown): CaseTransition {
  const v = obj(input);
  only(v, ["caseId", "expectedRevision",
    "expectedEvidenceFingerprint", "operation", "reason"]);
  if (!["START_REVIEW", "DISMISS",
    "COMPLETE_WORK", "REOPEN"].includes(String(v.operation)))
    fail("INVALID", "Unsupported asset review decision.");
  return {
    caseId: identifier(v.caseId, "ID"),
    expectedRevision: rev(v.expectedRevision),
    expectedEvidenceFingerprint: fingerprint(v.expectedEvidenceFingerprint),
    operation: v.operation as CaseDecision,
    reason: reason(v.reason),
  };
}
export function parseStepTransition(input: unknown): StepTransition {
  const v = obj(input);
  only(v, ["caseId", "actionCode", "expectedCaseRevision",
    "expectedStepRevision", "status", "note"]);
  if (!["TODO", "IN_PROGRESS", "BLOCKED", "DONE"].includes(
    String(v.status))) fail("INVALID", "Invalid checklist step status.");
  const actionCode = label(v.actionCode, "action code", 80);
  if (!/^[A-Z][A-Z0-9_]{2,79}$/.test(actionCode))
    fail("INVALID", "Malformed action code.");
  return {
    caseId: identifier(v.caseId, "ID"), actionCode,
    expectedCaseRevision: rev(v.expectedCaseRevision),
    expectedStepRevision: rev(v.expectedStepRevision),
    status: v.status as StepStatus, note: reason(v.note),
  };
}
export function parseCaseQuery(input: unknown = {}): CaseQuery {
  const v = obj(input);
  only(v, ["offset", "limit", "status", "importId", "inspectionId"]);
  const offset = v.offset ?? 0;
  const limit = v.limit ?? 25;
  if (typeof offset !== "number" ||
      !Number.isSafeInteger(offset) || offset < 0 || offset > 100000 ||
      typeof limit !== "number" || !Number.isSafeInteger(limit) ||
      limit < 1 || limit > 100)
    fail("INVALID", "Invalid case pagination.");
  if (v.status !== undefined && v.status !== null &&
      !statusOptions.includes(v.status as CaseStatus))
    fail("INVALID", "Unknown asset case status.");
  return {
    offset, limit, status: (v.status ?? null) as CaseStatus | null,
    importId: v.importId == null ? null : identifier(v.importId, "import ID"),
    inspectionId: v.inspectionId == null ? null :
      identifier(v.inspectionId, "inspection ID"),
  };
}
export function caseTransitionTarget(
  from: CaseStatus, action: CaseDecision,
): CaseStatus | null {
  if (from === "OPEN" && action === "START_REVIEW") return "IN_REVIEW";
  if ((from === "OPEN" || from === "IN_REVIEW") &&
      action === "DISMISS") return "DISMISSED";
  if (from === "IN_REVIEW" && action === "COMPLETE_WORK")
    return "WORK_COMPLETED";
  if ((from === "DISMISSED" || from === "WORK_COMPLETED") &&
      action === "REOPEN") return "OPEN";
  return null;
}
export function canCompleteCaseWork(
  steps: Array<{ status: string }>, category: string,
): boolean {
  if (category === "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION")
    return false;
  return steps.length > 0 && steps.every(x => x.status === "DONE");
}
function mapCase(row: {
  id: string; organizationId: string;
  importId: string; inspectionId: string;
  evidenceFingerprint: string;
  inventoryDigest: string; inspectionDigest: string;
  externalId: string; normalizedProductKey: string;
  softwareVersion: string | null;
  status: string; category: string; priority: string;
  revision: number; title: string;
  rationale: unknown; actions: unknown; advisoryIds: unknown;
  openedAt: Date; lastDecisionAt: Date | null;
  lastDecisionReason: string | null; lastDecisionUserId: string | null;
  steps: Array<{
    id: string; actionCode: string; status: string;
    revision: number; note: string | null;
    completedAt: Date | null; completedByUserId: string | null;
  }>;
}): CaseRow {
  return {
    id: row.id, organizationId: row.organizationId,
    importId: row.importId, inspectionId: row.inspectionId,
    evidenceFingerprint: row.evidenceFingerprint,
    inventoryDigest: row.inventoryDigest,
    inspectionDigest: row.inspectionDigest,
    externalId: row.externalId,
    normalizedProductKey: row.normalizedProductKey,
    softwareVersion: row.softwareVersion,
    status: row.status as CaseStatus,
    category: row.category, priority: row.priority,
    revision: row.revision, title: row.title,
    rationale: row.rationale, actions: row.actions,
    advisoryIds: row.advisoryIds,
    openedAt: row.openedAt.toISOString(),
    lastDecisionAt: row.lastDecisionAt?.toISOString() ?? null,
    lastDecisionReason: row.lastDecisionReason,
    lastDecisionUserId: row.lastDecisionUserId,
    steps: row.steps.map(step => ({
      id: step.id, actionCode: step.actionCode,
      status: step.status as StepStatus,
      revision: step.revision, note: step.note,
      completedAt: step.completedAt?.toISOString() ?? null,
      completedByUserId: step.completedByUserId,
    })),
  };
}
export async function listAssetAdviceCases(
  scope: AssetScope, input: unknown = {},
) {
  if (!canReadWork(scope.role))
    fail("FORBIDDEN", "Insufficient permissions to read asset cases.");
  const query = parseCaseQuery(input);
  const where = {
    organizationId: scope.organizationId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.importId ? { importId: query.importId } : {}),
    ...(query.inspectionId ? { inspectionId: query.inspectionId } : {}),
  };
  const [total, rows] = await db.$transaction([
    db.assetAdviceCase.count({ where }),
    db.assetAdviceCase.findMany({
      where, skip: query.offset, take: query.limit,
      orderBy: [{ updatedAt: "desc" }, { id: "desc" }],
      include: { steps: {
        orderBy: { actionCode: "asc" },
      } },
    }),
  ]);
  return {
    schema: "cyberpilot.assets.advice.cases.v1" as const,
    organizationId: scope.organizationId,
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + rows.length < total,
    cases: rows.map(mapCase),
    limitations: [
      "Work completion never confirms device remediation.",
      "Cases are separate from CyberScore and verified findings.",
      "This page shows only records belonging to the current organization.",
    ],
  };
}
export async function openAssetAdviceCase(
  scope: AssetScope, input: unknown,
  now = new Date(),
) {
  requireManager(scope);
  const command = parseCaseCreate(input);
  const guidance = parseAssetAdviceInput({
    importId: command.importId,
    inspectionId: command.inspectionId,
    bindings: command.bindings, limit: 100,
  });
  const snapshot = await readAssetAdviceSnapshot(scope, guidance);
  const rows = buildAssetAdviceRows(snapshot, guidance.bindings,
    guidance.maxObservationAgeDays, now);
  const chosen = rows.find(row =>
    row.evidenceFingerprint === command.evidenceFingerprint);
  if (!chosen)
    fail("CONFLICT",
      "Asset candidate has changed; refresh the provider-backed evidence preview.");
  if (chosen.status === "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION")
    fail("INVALID",
      "No-positive-match rows cannot be turned into vulnerability review cases.");
  const previous = await db.assetAdviceCase.findFirst({
    where: {
      organizationId: scope.organizationId,
      inspectionId: command.inspectionId,
      externalId: chosen.assetId,
      normalizedProductKey: chosen.normalizedProductKey,
    },
    include: { steps: true },
  });
  if (previous) {
    if (previous.evidenceFingerprint !== command.evidenceFingerprint)
      fail("CONFLICT",
        "This asset already has a review case for a different evidence fingerprint.");
    return {
      schema: "cyberpilot.assets.advice.case.open.v1" as const,
      replayed: true, case: mapCase(previous),
      warning: "Existing review was returned; no duplicate case or audit was created.",
    };
  }
  let created: Awaited<ReturnType<typeof db.assetAdviceCase.findFirst<{
    include: { steps: true };
  }>>>;
  try {
    created = await db.$transaction(async tx => {
    const row = await tx.assetAdviceCase.create({ data: {
      organizationId: scope.organizationId,
      importId: command.importId,
      inspectionId: command.inspectionId,
      evidenceFingerprint: chosen.evidenceFingerprint,
      inventoryDigest: chosen.inventoryDigest,
      inspectionDigest: chosen.inspectionDigest,
      externalId: chosen.assetId,
      normalizedProductKey: chosen.normalizedProductKey,
      softwareVersion: chosen.version,
      category: chosen.status, priority: chosen.priority,
      title: (chosen.product + " · " + chosen.assetId).slice(0, 220),
      rationale: JSON.parse(JSON.stringify({
        reasons: chosen.reasons,
        providerStatus: chosen.providerStatus,
        confidence: chosen.confidence,
        humanOpeningReason: command.reason,
      })),
      actions: JSON.parse(JSON.stringify(chosen.actions)),
      advisoryIds: chosen.possibleIds,
      openedAt: now,
      steps: { create: chosen.actions.map(action => ({
        organizationId: scope.organizationId,
        actionCode: action.code,
        status: "TODO",
      })) },
    }, include: { steps: true } });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assets.advice.case.opened",
      resourceType: "AssetAdviceCase", resourceId: row.id,
      metadata: {
        schema: "cyberpilot.assets.advice.case.audit.v1",
        inspectionId: command.inspectionId,
        importId: command.importId,
        evidenceFingerprint: chosen.evidenceFingerprint,
        category: chosen.status,
        reason: command.reason,
        notSecurityFinding: true,
      },
    } });
    return row;
    });
  } catch (cause) {
    if (cause && typeof cause === "object" &&
        "code" in cause && cause.code === "P2002") {
      const duplicate = await db.assetAdviceCase.findFirst({
        where: {
          organizationId: scope.organizationId,
          inspectionId: command.inspectionId,
          externalId: chosen.assetId,
          normalizedProductKey: chosen.normalizedProductKey,
        }, include: { steps: true },
      });
      if (duplicate &&
          duplicate.evidenceFingerprint === chosen.evidenceFingerprint)
        return {
          schema: "cyberpilot.assets.advice.case.open.v1" as const,
          replayed: true, case: mapCase(duplicate),
          warning: "Concurrent identical opening was deduplicated by PostgreSQL.",
        };
      fail("CONFLICT",
        "Another operator opened a case with different evidence.");
    }
    throw cause;
  }
  if (!created) fail("CONFLICT", "Case persistence did not return a record.");
  return {
    schema: "cyberpilot.assets.advice.case.open.v1" as const,
    replayed: false, case: mapCase(created),
    warning: "A customer-declared candidate case was opened, not a verified security finding.",
  };
}
export async function changeAssetAdviceCase(
  scope: AssetScope, input: unknown,
  now = new Date(),
) {
  requireManager(scope);
  const cmd = parseCaseTransition(input);
  const existing = await db.assetAdviceCase.findFirst({
    where: { id: cmd.caseId, organizationId: scope.organizationId },
    include: { steps: true },
  });
  if (!existing) fail("MISSING", "Review case not found.");
  if (existing.revision !== cmd.expectedRevision ||
      existing.evidenceFingerprint !== cmd.expectedEvidenceFingerprint)
    fail("CONFLICT", "Review case has changed since last inspection.");
  const next = caseTransitionTarget(
    existing.status as CaseStatus, cmd.operation);
  if (!next) fail("CONFLICT",
    "Invalid review case lifecycle transition.");
  if (cmd.operation === "COMPLETE_WORK" &&
      !canCompleteCaseWork(existing.steps, existing.category))
    fail("CONFLICT",
      "Finish all human checklist steps before marking work complete.");
  const updated = await db.$transaction(async tx => {
    const changed = await tx.assetAdviceCase.updateMany({
      where: {
        id: existing.id, organizationId: scope.organizationId,
        revision: cmd.expectedRevision,
        status: existing.status,
        evidenceFingerprint: cmd.expectedEvidenceFingerprint,
      },
      data: {
        status: next, revision: { increment: 1 },
        lastDecisionAt: now, lastDecisionUserId: scope.userId,
        lastDecisionReason: cmd.reason,
      },
    });
    if (changed.count !== 1)
      fail("CONFLICT", "Concurrent review decision detected.");
    const current = await tx.assetAdviceCase.findUniqueOrThrow({
      where: { id: existing.id },
      include: { steps: true },
    });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assets.advice.case." + cmd.operation.toLowerCase(),
      resourceType: "AssetAdviceCase",
      resourceId: existing.id,
      metadata: {
        schema: "cyberpilot.assets.advice.case.audit.v1",
        priorStatus: existing.status, nextStatus: next,
        reason: cmd.reason,
        revisionBefore: existing.revision,
        revisionAfter: current.revision,
        evidenceFingerprint: cmd.expectedEvidenceFingerprint,
        verifiedRemediation: false,
      },
    } });
    return current;
  });
  return {
    schema: "cyberpilot.assets.advice.case.transition.v1" as const,
    case: mapCase(updated), operation: cmd.operation,
    changed: true, auditRecorded: true,
    findingsChanged: false, cyberScoreChanged: false,
    providerQueried: false, remediationVerified: false,
  };
}
export async function changeAssetAdviceStep(
  scope: AssetScope, input: unknown,
  now = new Date(),
) {
  requireManager(scope);
  const cmd = parseStepTransition(input);
  const existing = await db.assetAdviceCase.findFirst({
    where: { id: cmd.caseId, organizationId: scope.organizationId },
    include: { steps: true },
  });
  if (!existing) fail("MISSING", "Review case not found.");
  if (existing.revision !== cmd.expectedCaseRevision)
    fail("CONFLICT", "Case revision differs from the reviewed version.");
  if (existing.status !== "IN_REVIEW")
    fail("CONFLICT",
      "Checklist changes are allowed only during active human review.");
  const step = existing.steps.find(row => row.actionCode === cmd.actionCode);
  if (!step) fail("MISSING", "Action is not part of this review case.");
  if (step.revision !== cmd.expectedStepRevision)
    fail("CONFLICT", "Checklist item changed concurrently.");
  if (step.status === cmd.status)
    fail("CONFLICT", "Checklist item already has the requested status.");
  const result = await db.$transaction(async tx => {
    const updated = await tx.assetAdviceCaseStep.updateMany({
      where: {
        id: step.id, organizationId: scope.organizationId,
        caseId: existing.id, revision: cmd.expectedStepRevision,
        status: step.status,
      },
      data: {
        status: cmd.status, revision: { increment: 1 },
        note: cmd.note,
        completedAt: cmd.status === "DONE" ? now : null,
        completedByUserId: cmd.status === "DONE" ? scope.userId : null,
      },
    });
    if (updated.count !== 1)
      fail("CONFLICT", "Concurrent checklist change detected.");
    const cas = await tx.assetAdviceCase.updateMany({
      where: {
        id: existing.id, organizationId: scope.organizationId,
        revision: cmd.expectedCaseRevision,
        status: "IN_REVIEW",
      },
      data: { revision: { increment: 1 } },
    });
    if (cas.count !== 1)
      fail("CONFLICT", "Concurrent case change detected.");
    const refreshed = await tx.assetAdviceCase.findUniqueOrThrow({
      where: { id: existing.id }, include: { steps: true },
    });
    await tx.auditEvent.create({ data: {
      organizationId: scope.organizationId,
      actorType: "USER", actorUserId: scope.userId,
      action: "assets.advice.case.step.updated",
      resourceType: "AssetAdviceCaseStep", resourceId: step.id,
      metadata: {
        schema: "cyberpilot.assets.advice.case.step.audit.v1",
        caseId: existing.id, code: step.actionCode,
        previousStatus: step.status, nextStatus: cmd.status,
        note: cmd.note, verifiedRemediation: false,
      },
    } });
    return refreshed;
  });
  return {
    schema: "cyberpilot.assets.advice.case.step.v1" as const,
    case: mapCase(result), actionCode: cmd.actionCode,
    stepStatus: cmd.status, auditRecorded: true,
    verifiedRemediation: false,
    findingsChanged: false, cyberScoreChanged: false,
  };
}
