import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Operational evidence gate. Decisions are human assessments of stored
 * observations, not independent provider verification.
 */
export type EvidenceGateStatus =
  | "NO_ASSESSMENT" | "REJECTED" | "INCONCLUSIVE"
  | "STALE_OBSERVATION" | "ACCEPTED_OBSERVATION";
export type EvidenceGateItem = {
  evidenceId: string;
  assessmentId: string | null;
  status: EvidenceGateStatus;
  reason: string;
  source: string | null;
  controlId: string | null;
  observedAt: string | null;
  assessedAt: string | null;
  assessorUserId: string | null;
  assessmentRevision: number | null;
};
export type ReviewEvidenceGate = {
  taskId: string;
  captureId: string;
  disposition: string;
  required: boolean;
  reviewRevision: number;
  assessmentRevision: number;
  gate: "NO_EVIDENCE" | "ACTION_REQUIRED" | "HUMAN_ACCEPTED";
  acceptedCount: number;
  rejectedCount: number;
  inconclusiveCount: number;
  staleCount: number;
  missingCount: number;
  items: EvidenceGateItem[];
  limitations: string[];
};
export type GatePortfolioQuery = {
  captureId?: string;
  offset: number;
  limit: number;
  includeResolved: boolean;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid gate query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function read(scope: ReviewScope) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Review evidence access denied.");
}
export function parseGatePortfolioQuery(value: unknown): GatePortfolioQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit", "includeResolved",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown gate query field.");
  if (raw.includeResolved !== undefined &&
      typeof raw.includeResolved !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeResolved flag.");
  return {
    ...(raw.captureId === undefined ? {} : {
      captureId: parseWorkId(raw.captureId, "capture ID"),
    }),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
    includeResolved: raw.includeResolved === true,
  };
}
type AssessmentRow = {
  id: string; evidenceId: string; decision: string;
  observationDigest: string; createdAt: Date;
  assessorUserId: string | null; revision: number;
  source: string; controlId: string; observedAt: Date | null;
};
type EvidenceRow = {
  id: string; state: string; observedAt: Date | null;
  source: string; domain: string; controlId: string; scope: string;
  schemaVersion: number; organizationId: string;
  updatedAt: Date; details: unknown;
};
function hashObservation(evidence: EvidenceRow) {
  // Keep digest semantics identical to the persistence service.
  const observation = {
    id: evidence.id, organizationId: evidence.organizationId,
    source: evidence.source, domain: evidence.domain,
    controlId: evidence.controlId, scope: evidence.scope,
    state: evidence.state, schemaVersion: evidence.schemaVersion,
    observedAt: evidence.observedAt?.toISOString() ?? null,
    updatedAt: evidence.updatedAt.toISOString(), details: evidence.details,
  };
  return observation;
}
import { createHash } from "node:crypto";
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function classifyAssessment(
  assessment: AssessmentRow | null,
  evidence: EvidenceRow | null,
): EvidenceGateItem {
  if (!assessment) {
    return {
      evidenceId: evidence?.id ?? "",
      assessmentId: null, status: "NO_ASSESSMENT",
      reason: "No human assessment exists for this evidence.",
      source: evidence?.source ?? null,
      controlId: evidence?.controlId ?? null,
      observedAt: evidence?.observedAt?.toISOString() ?? null,
      assessedAt: null, assessorUserId: null, assessmentRevision: null,
    };
  }
  const base = {
    evidenceId: assessment.evidenceId,
    assessmentId: assessment.id,
    source: assessment.source, controlId: assessment.controlId,
    observedAt: assessment.observedAt?.toISOString() ?? null,
    assessedAt: assessment.createdAt.toISOString(),
    assessorUserId: assessment.assessorUserId,
    assessmentRevision: assessment.revision,
  };
  if (assessment.decision === "REJECTED")
    return { ...base, status: "REJECTED",
      reason: "Latest human assessment rejected this observation." };
  if (assessment.decision !== "ACCEPTED")
    return { ...base, status: "INCONCLUSIVE",
      reason: "Latest human assessment was inconclusive." };
  if (!evidence || digest(hashObservation(evidence)) !== assessment.observationDigest)
    return { ...base, status: "STALE_OBSERVATION",
      reason: "The accepted observation has changed or is no longer available." };
  if (evidence.state !== "OBSERVED" || evidence.observedAt === null)
    return { ...base, status: "STALE_OBSERVATION",
      reason: "The current record is not a timestamped observation." };
  return { ...base, status: "ACCEPTED_OBSERVATION",
    reason: "Human acceptance matches the current stored observation." };
}
export function buildReviewEvidenceGate(
  task: {
    id: string; captureId: string; disposition: string;
    required: boolean; revision: number; assessmentRevision: number;
  },
  assessments: AssessmentRow[],
  evidence: EvidenceRow[],
): ReviewEvidenceGate {
  const latest = new Map<string, AssessmentRow>();
  for (const assessment of assessments) {
    const previous = latest.get(assessment.evidenceId);
    if (!previous || previous.revision < assessment.revision)
      latest.set(assessment.evidenceId, assessment);
  }
  const current = new Map(evidence.map(row => [row.id, row]));
  const items = [...latest.values()].map(assessment =>
    classifyAssessment(assessment, current.get(assessment.evidenceId) ?? null));
  const count = (status: EvidenceGateStatus) =>
    items.filter(item => item.status === status).length;
  const acceptedCount = count("ACCEPTED_OBSERVATION");
  const rejectedCount = count("REJECTED");
  const inconclusiveCount = count("INCONCLUSIVE");
  const staleCount = count("STALE_OBSERVATION");
  const missingCount = count("NO_ASSESSMENT");
  const gate = items.length === 0 ? "NO_EVIDENCE" :
    acceptedCount > 0 && rejectedCount === 0 &&
    inconclusiveCount === 0 && staleCount === 0 ?
      "HUMAN_ACCEPTED" : "ACTION_REQUIRED";
  return {
    taskId: task.id, captureId: task.captureId,
    disposition: task.disposition, required: task.required,
    reviewRevision: task.revision,
    assessmentRevision: task.assessmentRevision,
    gate, acceptedCount, rejectedCount, inconclusiveCount,
    staleCount, missingCount, items,
    limitations: [
      "HUMAN_ACCEPTED is a human decision, not an independent technical verification.",
      "No finding, remediation or CyberScore is changed by this gate.",
      "Only assessed evidence is included; absence of assessments is not evidence of security.",
    ],
  };
}
export async function getReviewEvidenceGate(scope: ReviewScope, taskId: string) {
  read(scope);
  const id = parseWorkId(taskId, "review task ID");
  const task = await db.integrityReviewTask.findFirst({
    where: { id, organizationId: scope.organizationId },
    select: {
      id: true, captureId: true, disposition: true,
      required: true, revision: true, assessmentRevision: true,
    },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const assessments = await db.integrityEvidenceAssessment.findMany({
    where: { organizationId: scope.organizationId, taskId: id },
    orderBy: [{ revision: "asc" }, { id: "asc" }],
    select: {
      id: true, evidenceId: true, decision: true,
      observationDigest: true, createdAt: true,
      assessorUserId: true, revision: true,
      source: true, controlId: true, observedAt: true,
    },
  });
  const evidenceIds = [...new Set(assessments.map(a => a.evidenceId))];
  const evidence = evidenceIds.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId, id: { in: evidenceIds },
    },
    select: {
      id: true, state: true, observedAt: true,
      source: true, domain: true, controlId: true,
      scope: true, schemaVersion: true, organizationId: true,
      updatedAt: true, details: true,
    },
  }) : [];
  return buildReviewEvidenceGate(task, assessments, evidence);
}
export async function listReviewEvidenceGates(
  scope: ReviewScope, value: unknown,
) {
  read(scope);
  const query = parseGatePortfolioQuery(value);
  const where = {
    organizationId: scope.organizationId,
    ...(query.captureId ? { captureId: query.captureId } : {}),
    ...(!query.includeResolved ? {
      disposition: { notIn: ["RESOLVED" as const, "WAIVED" as const] },
    } : {}),
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where,
      orderBy: [{ updatedAt: "desc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, captureId: true, disposition: true,
        required: true, revision: true, assessmentRevision: true,
      },
    }),
  ]);
  const taskIds = tasks.map(task => task.id);
  const assessments = taskIds.length ?
    await db.integrityEvidenceAssessment.findMany({
      where: {
        organizationId: scope.organizationId,
        taskId: { in: taskIds },
      },
      orderBy: [{ revision: "asc" }, { id: "asc" }],
      select: {
        id: true, taskId: true, evidenceId: true, decision: true,
        observationDigest: true, createdAt: true,
        assessorUserId: true, revision: true,
        source: true, controlId: true, observedAt: true,
      },
    }) : [];
  const evidenceIds = [...new Set(assessments.map(a => a.evidenceId))];
  const evidence = evidenceIds.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: evidenceIds },
    },
    select: {
      id: true, state: true, observedAt: true,
      source: true, domain: true, controlId: true,
      scope: true, schemaVersion: true, organizationId: true,
      updatedAt: true, details: true,
    },
  }) : [];
  const grouped = new Map<string, typeof assessments>();
  for (const assessment of assessments) {
    const bucket = grouped.get(assessment.taskId) ?? [];
    bucket.push(assessment);
    grouped.set(assessment.taskId, bucket);
  }
  const gates = tasks.map(task =>
    buildReviewEvidenceGate(task, grouped.get(task.id) ?? [], evidence));
  return {
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + gates.length < total,
    gates,
    summary: {
      humanAccepted: gates.filter(g => g.gate === "HUMAN_ACCEPTED").length,
      actionRequired: gates.filter(g => g.gate === "ACTION_REQUIRED").length,
      noEvidence: gates.filter(g => g.gate === "NO_EVIDENCE").length,
    },
    limitations: [
      "The summary applies only to the current page.",
      "Human acceptance does not prove independent remediation verification.",
    ],
  };
}
