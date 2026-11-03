import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { observationSnapshot } from "./work-integrity-evidence-assessment";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * A remote provider PASS is meaningful only while the exact bound evidence
 * observation remains unchanged and the result is within its TTL.
 * No database status or human acceptance is used as an independent proof.
 */
export type TechnicalGate =
  | "NO_CHECK" | "PROVIDER_ERROR" | "INCONCLUSIVE"
  | "FAILED" | "STALE" | "EXPIRED" | "PROVIDER_PASS";
export type TechnicalGateQuery = {
  taskId: string;
  maxAgeMinutes: number;
};
export type TechnicalGateResult = {
  taskId: string;
  gate: TechnicalGate;
  latestCheckId: string | null;
  provider: string | null;
  controlId: string | null;
  evidenceId: string | null;
  checkedAt: string | null;
  ageMinutes: number | null;
  observationMatches: boolean | null;
  sourceVerified: boolean;
  reason: string;
  limitations: string[];
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid technical gate query.");
  return value as Record<string, unknown>;
}
export function parseTechnicalGateQuery(value: unknown): TechnicalGateQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "taskId", "maxAgeMinutes",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown technical gate parameter.");
  const age = raw.maxAgeMinutes ?? 60;
  if (typeof age !== "number" || !Number.isSafeInteger(age) ||
      age < 1 || age > 1440)
    throw new WorkInputError("INVALID", "Invalid maximum check age.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    maxAgeMinutes: age,
  };
}
type Check = {
  id: string; evidenceId: string; provider: string;
  controlId: string; outcome: string; checkedAt: Date;
  observationDigest: string; failureCode: string | null;
};
type Evidence = {
  id: string; organizationId: string; source: string;
  domain: string; controlId: string; scope: string;
  state: string; schemaVersion: number;
  observedAt: Date | null; updatedAt: Date; details: unknown;
};
export function evaluateTechnicalGate(
  taskId: string,
  check: Check | null,
  evidence: Evidence | null,
  now: Date,
  maxAgeMinutes: number,
): TechnicalGateResult {
  const base = {
    taskId,
    latestCheckId: check?.id ?? null,
    provider: check?.provider ?? null,
    controlId: check?.controlId ?? null,
    evidenceId: check?.evidenceId ?? null,
    checkedAt: check?.checkedAt.toISOString() ?? null,
    ageMinutes: check ?
      Math.max(0, (now.getTime() - check.checkedAt.getTime()) / 60000) : null,
    observationMatches: check && evidence ?
      observationSnapshot(evidence).digest === check.observationDigest : null,
    sourceVerified: false,
    limitations: [
      "A provider PASS is a point-in-time observation, not a durable security guarantee.",
      "The result does not automatically close findings, work items or remediations.",
      "The gate requires the current evidence snapshot to match the checked snapshot.",
    ],
  };
  if (!check)
    return { ...base, gate: "NO_CHECK",
      reason: "No external provider verification has been recorded." };
  if (check.outcome === "PROVIDER_ERROR")
    return { ...base, gate: "PROVIDER_ERROR",
      reason: "The provider could not complete the verification." };
  if (check.outcome === "FAIL")
    return { ...base, gate: "FAILED",
      reason: "The provider reports the security control is not satisfied." };
  if (check.outcome !== "PASS")
    return { ...base, gate: "INCONCLUSIVE",
      reason: "The provider response is insufficient to verify the control." };
  if (!evidence || base.observationMatches !== true)
    return { ...base, gate: "STALE",
      reason: "The evidence observation changed after the provider check." };
  if (evidence.source !== check.provider ||
      evidence.controlId !== check.controlId ||
      evidence.state !== "OBSERVED" ||
      evidence.observedAt === null)
    return { ...base, gate: "STALE",
      reason: "The current evidence record no longer qualifies for this control." };
  if (check.checkedAt.getTime() > now.getTime() + 300000)
    return { ...base, gate: "INCONCLUSIVE",
      reason: "Provider check timestamp is unexpectedly in the future." };
  if (now.getTime() - check.checkedAt.getTime() >
      maxAgeMinutes * 60000)
    return { ...base, gate: "EXPIRED",
      reason: "The provider check exceeded the configured freshness window." };
  return { ...base, gate: "PROVIDER_PASS",
    sourceVerified: true,
    reason: "A fresh provider response passed and the evidence snapshot matches." };
}
export async function getTechnicalEvidenceGate(
  scope: ReviewScope, value: unknown,
  now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Technical evidence gate denied.");
  const query = parseTechnicalGateQuery(value);
  const task = await db.integrityReviewTask.findFirst({
    where: {
      id: query.taskId,
      organizationId: scope.organizationId,
    },
    select: { id: true },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const check = await db.integrityProviderCheck.findFirst({
    where: {
      organizationId: scope.organizationId,
      taskId: query.taskId,
    },
    orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
    select: {
      id: true, evidenceId: true, provider: true,
      controlId: true, outcome: true, checkedAt: true,
      observationDigest: true, failureCode: true,
    },
  });
  const evidence = check ? await db.securityEvidence.findFirst({
    where: {
      id: check.evidenceId,
      organizationId: scope.organizationId,
    },
  }) : null;
  return evaluateTechnicalGate(
    query.taskId, check, evidence, now, query.maxAgeMinutes);
}
export async function listCaptureTechnicalGates(
  scope: ReviewScope,
  value: unknown,
  now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Technical gate portfolio denied.");
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit", "maxAgeMinutes",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown technical gate filter.");
  const captureId = parseWorkId(raw.captureId, "capture ID");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 50;
  if (typeof offset !== "number" || !Number.isSafeInteger(offset) ||
      offset < 0 || offset > 1000000 ||
      typeof limit !== "number" || !Number.isSafeInteger(limit) ||
      limit < 1 || limit > 100)
    throw new WorkInputError("INVALID", "Invalid portfolio pagination.");
  const parsed = parseTechnicalGateQuery({
    taskId: captureId, maxAgeMinutes: raw.maxAgeMinutes,
  });
  const capture = await db.integrityCaseCapture.findFirst({
    where: {
      id: captureId, organizationId: scope.organizationId,
    },
    select: { id: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    captureId,
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: offset, take: limit,
      select: { id: true },
    }),
  ]);
  const taskIds = tasks.map(task => task.id);
  const checks = taskIds.length ? await db.integrityProviderCheck.findMany({
    where: {
      organizationId: scope.organizationId,
      taskId: { in: taskIds },
    },
    orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
    select: {
      id: true, taskId: true, evidenceId: true,
      provider: true, controlId: true, outcome: true,
      checkedAt: true, observationDigest: true, failureCode: true,
    },
  }) : [];
  const latest = new Map<string, typeof checks[number]>();
  for (const check of checks) {
    if (!latest.has(check.taskId))
      latest.set(check.taskId, check);
  }
  const evidenceIds = [...new Set([...latest.values()].map(x => x.evidenceId))];
  const evidence = evidenceIds.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: evidenceIds },
    },
  }) : [];
  const evidenceById = new Map(evidence.map(row => [row.id, row]));
  const gates = tasks.map(task => {
    const check = latest.get(task.id) ?? null;
    return evaluateTechnicalGate(
      task.id, check,
      check ? evidenceById.get(check.evidenceId) ?? null : null,
      now, parsed.maxAgeMinutes);
  });
  const counts: Record<TechnicalGate, number> = {
    NO_CHECK: 0, PROVIDER_ERROR: 0, INCONCLUSIVE: 0,
    FAILED: 0, STALE: 0, EXPIRED: 0, PROVIDER_PASS: 0,
  };
  for (const gate of gates) counts[gate.gate]++;
  return {
    captureId, total, offset, limit,
    hasMore: offset + gates.length < total,
    gates, summary: counts,
    limitations: [
      "Counts describe the current page only.",
      "Only the most recent provider check per task is used.",
      "A provider PASS does not automatically update security findings or scores.",
    ],
  };
}
