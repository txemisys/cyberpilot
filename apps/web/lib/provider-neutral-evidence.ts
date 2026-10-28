import { db } from "@cyberpilot/database";

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
