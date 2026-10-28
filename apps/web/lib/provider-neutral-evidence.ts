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
