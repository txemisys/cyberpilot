import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { evaluateTechnicalGate } from "./work-integrity-provider-gates";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Remediation readiness is a decision aid. It never performs a remediation
 * transition or resolves a security finding.
 *
 * Only evidence explicitly linked to BOTH the review and the work item
 * can qualify as provider-verified support for that work item.
 */
export type ReadinessState =
  | "UNLINKED" | "WORK_CANCELLED" | "REVIEW_WAIVED"
  | "WORK_INCOMPLETE" | "EVIDENCE_NOT_LINKED"
  | "NO_PROVIDER_CHECK" | "PROVIDER_FAILED"
  | "PROVIDER_STALE" | "PROVIDER_VERIFIED";
export type ReadinessInput = {
  taskId: string;
  maxAgeMinutes: number;
};
export type WorkReadiness = {
  taskId: string;
  workItemId: string;
  reviewDisposition: string;
  workStatus: string;
  remediationStatus: string;
  findingStatus: string;
  state: ReadinessState;
  providerVerifiedEvidenceIds: string[];
  blockedEvidenceIds: string[];
  linkedEvidenceIds: string[];
  latestProviderCheckIds: string[];
  canRequestHumanReview: boolean;
  canAutoResolve: false;
  reasons: string[];
};
export type WorkReadinessPortfolio = {
  taskId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  items: WorkReadiness[];
  summary: Record<ReadinessState, number>;
  limitations: string[];
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid readiness request.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseReadinessInput(value: unknown): ReadinessInput & {
  offset: number; limit: number; includeInactive: boolean;
} {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "taskId", "maxAgeMinutes", "offset", "limit", "includeInactive",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown readiness parameter.");
  if (raw.includeInactive !== undefined &&
      typeof raw.includeInactive !== "boolean")
    throw new WorkInputError("INVALID", "Invalid inactive link filter.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    maxAgeMinutes: integer(raw.maxAgeMinutes ?? 60,
      "maximum age", 1, 1440),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    includeInactive: raw.includeInactive === true,
  };
}
type Evidence = {
  id: string; organizationId: string; source: string;
  domain: string; controlId: string; scope: string;
  state: string; schemaVersion: number; observedAt: Date | null;
  updatedAt: Date; details: unknown;
};
type Check = {
  id: string; evidenceId: string; provider: string;
  controlId: string; outcome: string; checkedAt: Date;
  observationDigest: string; failureCode: string | null;
};
export type WorkReadinessRecord = {
  taskId: string; workItemId: string; unlinkedAt: Date | null;
  reviewDisposition: string;
  workStatus: string; remediationStatus: string; findingStatus: string;
  evidenceIds: string[];
};
function initialSummary(): Record<ReadinessState, number> {
  return {
    UNLINKED: 0, WORK_CANCELLED: 0, REVIEW_WAIVED: 0,
    WORK_INCOMPLETE: 0, EVIDENCE_NOT_LINKED: 0,
    NO_PROVIDER_CHECK: 0, PROVIDER_FAILED: 0,
    PROVIDER_STALE: 0, PROVIDER_VERIFIED: 0,
  };
}
export function evaluateWorkReadiness(
  record: WorkReadinessRecord,
  checks: Check[],
  evidence: Evidence[],
  now: Date,
  maxAgeMinutes: number,
): WorkReadiness {
  const latest = new Map<string, Check>();
  for (const check of checks) {
    const previous = latest.get(check.evidenceId);
    if (!previous || previous.checkedAt.getTime() < check.checkedAt.getTime() ||
        (previous.checkedAt.getTime() === check.checkedAt.getTime() &&
          previous.id < check.id))
      latest.set(check.evidenceId, check);
  }
  const evidenceById = new Map(evidence.map(row => [row.id, row]));
  const linkedEvidenceIds = [...new Set(record.evidenceIds)].sort();
  const verified: string[] = [];
  const blocked: string[] = [];
  const latestProviderCheckIds: string[] = [];
  const providerGates: string[] = [];
  for (const id of linkedEvidenceIds) {
    const check = latest.get(id) ?? null;
    if (check) latestProviderCheckIds.push(check.id);
    const gate = evaluateTechnicalGate(
      record.taskId, check, evidenceById.get(id) ?? null,
      now, maxAgeMinutes,
    );
    providerGates.push(gate.gate);
    if (gate.sourceVerified) verified.push(id);
    else blocked.push(id);
  }
  const reasons: string[] = [];
  let state: ReadinessState;
  if (record.unlinkedAt) {
    state = "UNLINKED";
    reasons.push("The review-to-work association is no longer active.");
  } else if (record.workStatus === "CANCELLED") {
    state = "WORK_CANCELLED";
    reasons.push("The operational work item was cancelled.");
  } else if (record.reviewDisposition === "WAIVED") {
    state = "REVIEW_WAIVED";
    reasons.push("The review was waived rather than independently verified.");
  } else if (record.workStatus !== "DONE") {
    state = "WORK_INCOMPLETE";
    reasons.push("The operational work item is not marked DONE.");
  } else if (!linkedEvidenceIds.length) {
    state = "EVIDENCE_NOT_LINKED";
    reasons.push("The work item has no active evidence associations.");
  } else if (!latestProviderCheckIds.length) {
    state = "NO_PROVIDER_CHECK";
    reasons.push("No linked evidence has a provider verification for this review.");
  } else if (providerGates.includes("FAILED")) {
    state = "PROVIDER_FAILED";
    reasons.push("A linked evidence record failed its latest provider check.");
  } else if (blocked.length) {
    state = "PROVIDER_STALE";
    reasons.push("At least one linked evidence record is not freshly provider-verified.");
  } else {
    state = "PROVIDER_VERIFIED";
    reasons.push("Every linked evidence record has a fresh matching provider check.");
  }
  if (record.findingStatus === "RESOLVED")
    reasons.push("The associated finding is already marked resolved; no state is changed.");
  if (record.remediationStatus === "VERIFIED")
    reasons.push("The remediation is marked verified independently of this assessment.");
  return {
    taskId: record.taskId, workItemId: record.workItemId,
    reviewDisposition: record.reviewDisposition,
    workStatus: record.workStatus,
    remediationStatus: record.remediationStatus,
    findingStatus: record.findingStatus,
    state, providerVerifiedEvidenceIds: verified,
    blockedEvidenceIds: blocked, linkedEvidenceIds,
    latestProviderCheckIds,
    canRequestHumanReview: state === "PROVIDER_VERIFIED",
    canAutoResolve: false,
    reasons,
  };
}
export async function inspectReviewWorkReadiness(
  scope: ReviewScope, value: unknown,
  now = new Date(),
): Promise<WorkReadinessPortfolio> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Readiness inspection denied.");
  const query = parseReadinessInput(value);
  const task = await db.integrityReviewTask.findFirst({
    where: { id: query.taskId, organizationId: scope.organizationId },
    select: { id: true, disposition: true },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const where = {
    organizationId: scope.organizationId,
    taskId: query.taskId,
    ...(query.includeInactive ? {} : { unlinkedAt: null }),
  };
  const [total, links] = await db.$transaction([
    db.integrityReviewWorkLink.count({ where }),
    db.integrityReviewWorkLink.findMany({
      where,
      orderBy: [{ linkedAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, taskId: true, workItemId: true, unlinkedAt: true,
        workItem: {
          select: {
            status: true,
            remediation: { select: { status: true } },
            finding: { select: { status: true } },
            evidenceLinks: {
              where: { unlinkedAt: null },
              select: { evidenceId: true },
            },
          },
        },
      },
    }),
  ]);
  const ids = [...new Set(links.flatMap(link =>
    link.workItem.evidenceLinks.map(row => row.evidenceId)))];
  const checks = ids.length ? await db.integrityProviderCheck.findMany({
    where: {
      organizationId: scope.organizationId,
      taskId: query.taskId,
      evidenceId: { in: ids },
    },
    select: {
      id: true, evidenceId: true, provider: true,
      controlId: true, outcome: true, checkedAt: true,
      observationDigest: true, failureCode: true,
    },
  }) : [];
  const evidence = ids.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: ids },
    },
  }) : [];
  const items = links.map(link => evaluateWorkReadiness({
    taskId: link.taskId,
    workItemId: link.workItemId,
    unlinkedAt: link.unlinkedAt,
    reviewDisposition: task.disposition,
    workStatus: link.workItem.status,
    remediationStatus: link.workItem.remediation.status,
    findingStatus: link.workItem.finding.status,
    evidenceIds: link.workItem.evidenceLinks.map(row => row.evidenceId),
  }, checks, evidence, now, query.maxAgeMinutes));
  const summary = initialSummary();
  for (const item of items) summary[item.state]++;
  return {
    taskId: query.taskId, total, offset: query.offset,
    limit: query.limit, hasMore: query.offset + items.length < total,
    items, summary,
    limitations: [
      "Only explicitly linked active evidence records are evaluated.",
      "A provider PASS is a point-in-time observation with a bounded TTL.",
      "Readiness never changes the review, work item, finding, remediation or CyberScore.",
      "Summary counts describe the current page only.",
    ],
  };
}
