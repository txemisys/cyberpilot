import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * A human assessment records the exact evidence snapshot considered.
 * ACCEPTED means the assessor accepted that snapshot for this task.
 * It does not independently attest the external control's security state.
 */
export type EvidenceDecision = "ACCEPTED" | "REJECTED" | "INCONCLUSIVE";
export type AssessmentInput = {
  taskId: string;
  evidenceId: string;
  expectedRevision: number;
  decision: EvidenceDecision;
  rationale: string;
  idempotencyKey: string;
};
export type AssessmentQuery = {
  taskId: string;
  offset: number;
  limit: number;
};
const decisions: EvidenceDecision[] = ["ACCEPTED", "REJECTED", "INCONCLUSIVE"];

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Assessment must be an object.");
  return value as Record<string, unknown>;
}
function strict(raw: Record<string, unknown>, keys: string[]) {
  const extra = Object.keys(raw).find(key => !keys.includes(key));
  if (extra) throw new WorkInputError("INVALID", "Unknown assessment field: " + extra);
}
function text(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "string" || value.trim().length < min ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value.trim();
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function assertRead(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Assessment access denied.");
}
function assertWrite(scope: ReviewScope) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Assessment requires OWNER or ADMIN.");
}
export function parseAssessment(value: unknown): AssessmentInput {
  const raw = object(value);
  strict(raw, ["taskId", "evidenceId", "expectedRevision",
    "decision", "rationale", "idempotencyKey"]);
  if (!decisions.includes(raw.decision as EvidenceDecision))
    throw new WorkInputError("INVALID", "Unknown assessment decision.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    evidenceId: parseWorkId(raw.evidenceId, "evidence ID"),
    expectedRevision: integer(raw.expectedRevision, "expected revision", 1, 2147483646),
    decision: raw.decision as EvidenceDecision,
    rationale: text(raw.rationale, "rationale", 12, 4000),
    idempotencyKey: text(raw.idempotencyKey, "idempotency key", 8, 160),
  };
}
export function parseAssessmentQuery(value: unknown): AssessmentQuery {
  const raw = object(value);
  strict(raw, ["taskId", "offset", "limit"]);
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
  };
}
export function observationSnapshot(evidence: {
  id: string; organizationId: string; source: string; domain: string;
  controlId: string; scope: string; state: string; schemaVersion: number;
  observedAt: Date | null; updatedAt: Date; details: unknown;
}) {
  const observation = {
    id: evidence.id,
    organizationId: evidence.organizationId,
    source: evidence.source,
    domain: evidence.domain,
    controlId: evidence.controlId,
    scope: evidence.scope,
    state: evidence.state,
    schemaVersion: evidence.schemaVersion,
    observedAt: evidence.observedAt?.toISOString() ?? null,
    updatedAt: evidence.updatedAt.toISOString(),
    details: evidence.details,
  };
  return { digest: hash(observation), observation };
}
export function assessEvidencePolicy(input: {
  decision: EvidenceDecision;
  state: string;
  observedAt: Date | null;
  taskDisposition: string;
}) {
  if (input.taskDisposition === "WAIVED")
    throw new WorkInputError("CONFLICT", "Waived tasks cannot accept assessments.");
  if (input.taskDisposition === "RESOLVED")
    throw new WorkInputError("CONFLICT", "Reopen the review before assessing evidence.");
  if (input.decision === "ACCEPTED" &&
      (input.state !== "OBSERVED" || input.observedAt === null))
    throw new WorkInputError("CONFLICT",
      "Acceptance requires a timestamped OBSERVED evidence record.");
}
async function existingAssessment(
  scope: ReviewScope, key: string, requestDigest: string,
) {
  const prior = await db.integrityEvidenceAssessment.findFirst({
    where: {
      organizationId: scope.organizationId,
      assessorUserId: scope.userId,
      idempotencyKey: key,
    },
  });
  if (!prior) return null;
  if (prior.requestDigest !== requestDigest)
    throw new WorkInputError("CONFLICT",
      "Idempotency key already used for a different assessment.");
  return prior;
}
function isConflict(error: unknown) {
  return typeof error === "object" && error !== null &&
    "code" in error && (error.code === "P2002" || error.code === "P2034");
}
export async function recordEvidenceAssessment(
  scope: ReviewScope, value: unknown,
) {
  assertWrite(scope);
  const input = parseAssessment(value);
  const requestDigest = hash(input);
  const replay = await existingAssessment(scope, input.idempotencyKey, requestDigest);
  if (replay) return { replayed: true, assessment: replay };
  try {
    const assessment = await db.$transaction(async tx => {
      const task = await tx.integrityReviewTask.findFirst({
        where: { id: input.taskId, organizationId: scope.organizationId },
        select: {
          id: true, disposition: true, revision: true,
          captureId: true,
        },
      });
      if (!task)
        throw new WorkInputError("MISSING", "Review task not found.");
      if (task.revision !== input.expectedRevision)
        throw new WorkInputError("CONFLICT", "Review revision changed.");
      const evidence = await tx.securityEvidence.findFirst({
        where: { id: input.evidenceId, organizationId: scope.organizationId },
        select: {
          id: true, organizationId: true, source: true,
          domain: true, controlId: true, scope: true, state: true,
          schemaVersion: true, observedAt: true, updatedAt: true,
          details: true,
        },
      });
      if (!evidence)
        throw new WorkInputError("MISSING", "Evidence not found.");
      assessEvidencePolicy({
        decision: input.decision,
        state: evidence.state,
        observedAt: evidence.observedAt,
        taskDisposition: task.disposition,
      });
      const snapshot = observationSnapshot(evidence);
      // Bump the task revision to serialize assessment with state transitions.
      // This is not a transition to RESOLVED and cannot close a finding.
      const claimed = await tx.integrityReviewTask.updateMany({
        where: {
          id: task.id, organizationId: scope.organizationId,
          revision: input.expectedRevision,
          disposition: task.disposition,
        },
        data: { revision: { increment: 1 } },
      });
      if (claimed.count !== 1)
        throw new WorkInputError("CONFLICT", "Concurrent review update.");
      const saved = await tx.integrityEvidenceAssessment.create({
        data: {
          organizationId: scope.organizationId,
          taskId: task.id,
          evidenceId: evidence.id,
          assessorUserId: scope.userId,
          decision: input.decision,
          rationale: input.rationale,
          observationDigest: snapshot.digest,
          observedAt: evidence.observedAt,
          source: evidence.source,
          controlId: evidence.controlId,
          evidenceState: evidence.state,
          evidenceUpdatedAt: evidence.updatedAt,
          revision: task.revision + 1,
          idempotencyKey: input.idempotencyKey,
          requestDigest,
        },
      });
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER",
          actorUserId: scope.userId,
          action: "integrity.evidence.assessed",
          resourceType: "IntegrityEvidenceAssessment",
          resourceId: saved.id,
          metadata: {
            taskId: task.id,
            captureId: task.captureId,
            evidenceId: evidence.id,
            decision: input.decision,
            observationDigest: snapshot.digest,
            revision: saved.revision,
          },
        },
      });
      return saved;
    }, { isolationLevel: "Serializable" });
    return { replayed: false, assessment };
  } catch (error) {
    if (isConflict(error)) {
      const prior = await existingAssessment(
        scope, input.idempotencyKey, requestDigest,
      );
      if (prior) return { replayed: true, assessment: prior };
      throw new WorkInputError("CONFLICT", "Concurrent assessment; reload and retry.");
    }
    throw error;
  }
}
export async function listEvidenceAssessments(
  scope: ReviewScope, value: unknown,
) {
  assertRead(scope);
  const query = parseAssessmentQuery(value);
  const task = await db.integrityReviewTask.findFirst({
    where: { id: query.taskId, organizationId: scope.organizationId },
    select: { id: true, revision: true, disposition: true },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const where = { organizationId: scope.organizationId, taskId: query.taskId };
  const [total, assessments] = await db.$transaction([
    db.integrityEvidenceAssessment.count({ where }),
    db.integrityEvidenceAssessment.findMany({
      where,
      orderBy: [{ revision: "asc" }, { id: "asc" }],
      skip: query.offset,
      take: query.limit,
      select: {
        id: true, taskId: true, evidenceId: true,
        assessorUserId: true, decision: true, rationale: true,
        observationDigest: true, observedAt: true, source: true,
        controlId: true, evidenceState: true, evidenceUpdatedAt: true,
        revision: true, createdAt: true,
      },
    }),
  ]);
  return {
    task, total, assessments, offset: query.offset, limit: query.limit,
    hasMore: query.offset + assessments.length < total,
    limitations: [
      "Assessment records a human decision about a stored observation.",
      "No independent provider recheck, cryptographic attestation or remediation verification is implied.",
    ],
  };
}
export async function inspectAssessmentEvidence(
  scope: ReviewScope, assessmentId: string,
) {
  assertRead(scope);
  const id = parseWorkId(assessmentId, "assessment ID");
  const assessment = await db.integrityEvidenceAssessment.findFirst({
    where: { id, organizationId: scope.organizationId },
  });
  if (!assessment)
    throw new WorkInputError("MISSING", "Assessment not found.");
  const evidence = await db.securityEvidence.findFirst({
    where: { id: assessment.evidenceId, organizationId: scope.organizationId },
    select: {
      id: true, organizationId: true, source: true, domain: true,
      controlId: true, scope: true, state: true, schemaVersion: true,
      observedAt: true, updatedAt: true, details: true,
    },
  });
  const current = evidence ? observationSnapshot(evidence) : null;
  const audit = await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceType: "IntegrityEvidenceAssessment",
      resourceId: assessment.id,
      action: "integrity.evidence.assessed",
    },
    select: { id: true, actorUserId: true, metadata: true },
    take: 2,
  });
  const auditMatches = audit.length === 1 &&
    audit[0]?.actorUserId === assessment.assessorUserId &&
    typeof audit[0].metadata === "object" &&
    audit[0].metadata !== null &&
    !Array.isArray(audit[0].metadata) &&
    (audit[0].metadata as Record<string, unknown>).observationDigest ===
      assessment.observationDigest;
  return {
    assessment,
    auditMatches,
    currentObservationDigest: current?.digest ?? null,
    observationUnchanged: current?.digest === assessment.observationDigest,
    consistent: auditMatches && current?.digest === assessment.observationDigest,
    limitations: [
      "A changed observation invalidates the snapshot match, not the historical assessment.",
      "Database audit matching is not a cryptographic signature.",
    ],
  };
}
