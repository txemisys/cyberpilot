import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";
import { observationSnapshot } from "./work-integrity-evidence-assessment";

/**
 * Read-only provider-check integrity inspector. A valid audit chain
 * establishes local persistence consistency, not external authenticity.
 */
export type ProviderCheckInspection = {
  checkId: string;
  taskId: string;
  evidenceId: string;
  provider: string;
  outcome: string;
  checkedAt: string;
  evidenceMatches: boolean;
  auditConsistent: boolean;
  findings: string[];
  limitations: string[];
};
type Check = {
  id: string; organizationId: string; taskId: string;
  evidenceId: string; provider: string; controlId: string;
  subject: string; outcome: string; checkedAt: Date;
  requestDigest: string; responseDigest: string;
  observationDigest: string; requestedByUserId: string | null;
};
type Audit = {
  organizationId: string; action: string;
  resourceId: string | null; actorUserId: string | null;
  metadata: unknown;
};
export function inspectProviderCheckRecord(
  check: Check,
  audit: Audit | null,
  evidenceDigest: string | null,
): ProviderCheckInspection {
  const findings: string[] = [];
  if (!audit) findings.push("MISSING_AUDIT");
  else {
    if (audit.organizationId !== check.organizationId)
      findings.push("CROSS_TENANT_AUDIT");
    if (audit.resourceId !== check.id ||
        audit.action !== "integrity.provider.google_2sv.check")
      findings.push("AUDIT_RESOURCE_MISMATCH");
    if (audit.actorUserId !== check.requestedByUserId)
      findings.push("AUDIT_ACTOR_MISMATCH");
    const raw = audit.metadata;
    const data = raw && typeof raw === "object" &&
      !Array.isArray(raw) ? raw as Record<string, unknown> : {};
    if (data.taskId !== check.taskId ||
        data.evidenceId !== check.evidenceId ||
        data.provider !== check.provider ||
        data.controlId !== check.controlId ||
        data.subject !== check.subject)
      findings.push("AUDIT_SUBJECT_MISMATCH");
    if (data.requestDigest !== check.requestDigest ||
        data.responseDigest !== check.responseDigest ||
        data.observationDigest !== check.observationDigest)
      findings.push("AUDIT_DIGEST_MISMATCH");
    if (data.outcome !== check.outcome)
      findings.push("AUDIT_OUTCOME_MISMATCH");
  }
  if (!evidenceDigest)
    findings.push("EVIDENCE_UNAVAILABLE");
  else if (evidenceDigest !== check.observationDigest)
    findings.push("EVIDENCE_CHANGED");
  if (!/^[a-f0-9]{64}$/.test(check.requestDigest) ||
      !/^[a-f0-9]{64}$/.test(check.responseDigest) ||
      !/^[a-f0-9]{64}$/.test(check.observationDigest))
    findings.push("INVALID_DIGEST");
  return {
    checkId: check.id, taskId: check.taskId,
    evidenceId: check.evidenceId,
    provider: check.provider, outcome: check.outcome,
    checkedAt: check.checkedAt.toISOString(),
    evidenceMatches: evidenceDigest === check.observationDigest,
    auditConsistent: findings.length === 0,
    findings: [...new Set(findings)],
    limitations: [
      "Audit consistency does not independently authenticate the provider response.",
      "The stored provider response is represented by a digest and selected metadata.",
      "A valid historical provider PASS is not a guarantee of current security.",
    ],
  };
}
export async function inspectProviderCheck(
  scope: ReviewScope, checkId: string,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Provider inspection denied.");
  const id = parseWorkId(checkId, "provider check ID");
  const check = await db.integrityProviderCheck.findFirst({
    where: { id, organizationId: scope.organizationId },
  });
  if (!check)
    throw new WorkInputError("MISSING", "Provider check not found.");
  const [audit, evidence] = await Promise.all([
    db.auditEvent.findFirst({
      where: {
        organizationId: scope.organizationId,
        resourceType: "IntegrityProviderCheck",
        resourceId: check.id,
        action: "integrity.provider.google_2sv.check",
      },
      orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
      select: {
        organizationId: true, action: true,
        resourceId: true, actorUserId: true,
        metadata: true,
      },
    }),
    db.securityEvidence.findFirst({
      where: {
        id: check.evidenceId, organizationId: scope.organizationId,
      },
    }),
  ]);
  return inspectProviderCheckRecord(
    check, audit,
    evidence ? observationSnapshot(evidence).digest : null,
  );
}
export async function inspectCaptureProviderChecks(
  scope: ReviewScope,
  value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Provider inspection denied.");
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid inspection query.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown inspection field.");
  const captureId = parseWorkId(raw.captureId, "capture ID");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 50;
  if (typeof offset !== "number" || !Number.isSafeInteger(offset) ||
      offset < 0 || offset > 1000000 ||
      typeof limit !== "number" || !Number.isSafeInteger(limit) ||
      limit < 1 || limit > 100)
    throw new WorkInputError("INVALID", "Invalid inspection pagination.");
  const capture = await db.integrityCaseCapture.findFirst({
    where: { id: captureId, organizationId: scope.organizationId },
    select: { id: true },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    task: { captureId },
  };
  const [total, checks] = await db.$transaction([
    db.integrityProviderCheck.count({ where }),
    db.integrityProviderCheck.findMany({
      where,
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      skip: offset, take: limit,
    }),
  ]);
  const ids = checks.map(check => check.id);
  const audits = ids.length ? await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceType: "IntegrityProviderCheck",
      resourceId: { in: ids },
      action: "integrity.provider.google_2sv.check",
    },
    orderBy: [{ occurredAt: "asc" }, { id: "asc" }],
    select: {
      organizationId: true, action: true,
      resourceId: true, actorUserId: true, metadata: true,
    },
  }) : [];
  const evidenceIds = [...new Set(checks.map(check => check.evidenceId))];
  const evidence = evidenceIds.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: evidenceIds },
    },
  }) : [];
  const byEvidence = new Map(evidence.map(row => [
    row.id, observationSnapshot(row).digest,
  ]));
  const byAudit = new Map(audits.map(row => [row.resourceId, row]));
  const inspections = checks.map(check => inspectProviderCheckRecord(
    check, byAudit.get(check.id) ?? null,
    byEvidence.get(check.evidenceId) ?? null,
  ));
  const findings: Record<string, number> = {};
  for (const inspection of inspections) {
    for (const finding of inspection.findings)
      findings[finding] = (findings[finding] ?? 0) + 1;
  }
  return {
    captureId, total, offset, limit,
    hasMore: offset + inspections.length < total,
    inspections,
    summary: {
      checked: inspections.length,
      consistent: inspections.filter(row => row.auditConsistent).length,
      inconsistent: inspections.filter(row => !row.auditConsistent).length,
      findings,
    },
    limitations: [
      "The inspection checks local records and their audit events.",
      "No remote provider call is made during historical inspection.",
      "Counts describe the current page only.",
    ],
  };
}
