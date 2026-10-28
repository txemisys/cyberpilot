import { db } from "@cyberpilot/database";
import {
  summarizeEvidenceCoverage,
  type SecurityEvidenceV1,
  type EvidenceDomain,
  type EvidenceSource,
  type EvidenceState,
} from "@cyberpilot/risk-engine";

const EVIDENCE_SOURCES: readonly EvidenceSource[] = ["MICROSOFT_365", "DOMAIN", "BASELINE", "ASSETS", "GOOGLE_WORKSPACE", "LAB"];
const EVIDENCE_DOMAINS: readonly EvidenceDomain[] = ["IDENTITY", "EMAIL", "WEB", "ENDPOINT", "BACKUP", "GOVERNANCE"];
const EVIDENCE_STATES: readonly EvidenceState[] = ["OBSERVED", "DECLARED", "UNKNOWN", "ERROR"];


/**
 * Server-side read boundary for provider-neutral evidence.
 * Never query these records without both the requesting user and organization.
 * No HTTP route is exposed by this module.
 */
export async function listOrganizationEvidenceForUser(
  organizationId: string,
  userId: string,
) {
  const membership = await db.membership.findUnique({
    where: { organizationId_userId: { organizationId, userId } },
    select: { organizationId: true },
  });
  if (!membership) {
    return null;
  }
  return db.securityEvidence.findMany({
    where: { organizationId: membership.organizationId },
    orderBy: [{ domain: "asc" }, { controlId: "asc" }, { scope: "asc" }],
  });
}

/** Internal only: external evidence ingestion must use a separate trusted adapter. */
export async function upsertDeclaredOrganizationEvidenceForUser(
  organizationId: string,
  userId: string,
  input: {
    domain: "IDENTITY" | "EMAIL" | "WEB" | "ENDPOINT" | "BACKUP" | "GOVERNANCE";
    controlId: string;
    scope: string;
    details: Record<string, string | number | boolean | null>;
  },
) {
  if (!input.controlId.trim() || !input.scope.trim()) return null;
  const membership = await db.membership.findUnique({
    where: { organizationId_userId: { organizationId, userId } },
    select: { role: true },
  });
  if (!membership || (membership.role !== "OWNER" && membership.role !== "ADMIN")) {
    return null;
  }
  return db.$transaction(async (tx) => {
    const evidence = await tx.securityEvidence.upsert({
      where: {
        organizationId_source_domain_controlId_scope: {
          organizationId, source: "BASELINE", domain: input.domain,
          controlId: input.controlId.trim(), scope: input.scope.trim(),
        },
      },
      create: {
        organizationId, source: "BASELINE", domain: input.domain,
        controlId: input.controlId.trim(), scope: input.scope.trim(),
        state: "DECLARED", observedAt: null, details: input.details,
      },
      update: { state: "DECLARED", observedAt: null, details: input.details },
    });
    await tx.auditEvent.create({
      data: {
        organizationId, actorType: "USER", actorUserId: userId,
        action: "evidence.baseline.declared_upsert",
        resourceType: "SecurityEvidence", resourceId: evidence.id,
        metadata: { domain: input.domain, controlId: input.controlId.trim() },
      },
    });
    return evidence;
  });
}

/**
 * A scoped, read-only coverage view for future Exposure/Baseline reports.
 * Unknown database values fail closed instead of being counted as observations.
 * No impact on the existing M365 CyberScore until a versioned migration.
 */
export async function getOrganizationEvidenceCoverageForUser(
  organizationId: string,
  userId: string,
  expectedDomains: readonly EvidenceDomain[],
) {
  const records = await listOrganizationEvidenceForUser(organizationId, userId);
  if (records === null) return null;
  const evidence: SecurityEvidenceV1[] = records
    .filter((record) =>
      record.schemaVersion === 1 &&
      EVIDENCE_SOURCES.includes(record.source as EvidenceSource) &&
      EVIDENCE_DOMAINS.includes(record.domain as EvidenceDomain) &&
      EVIDENCE_STATES.includes(record.state as EvidenceState) &&
      (record.state !== "OBSERVED" || record.observedAt !== null),
    )
    .map((record) => ({
      schemaVersion: 1,
      organizationId: record.organizationId,
      source: record.source as EvidenceSource,
      domain: record.domain as EvidenceDomain,
      controlId: record.controlId,
      state: record.state as EvidenceState,
      observedAt: record.observedAt,
      scope: record.scope,
      details: {},
    }));
  return summarizeEvidenceCoverage(evidence, expectedDomains);
}
