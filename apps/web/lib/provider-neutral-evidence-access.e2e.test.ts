import { describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { listOrganizationEvidenceForUser } from "./provider-neutral-evidence";

describe("provider-neutral evidence authorization", () => {
  it("rejects strangers and isolates data for a user with access to two organizations", async () => {
    const nonce = crypto.randomUUID();
    const owner = await db.user.create({ data: { name: "Owner", email: `evidence-owner-${nonce}@example.test` } });
    const stranger = await db.user.create({ data: { name: "Stranger", email: `evidence-stranger-${nonce}@example.test` } });
    const a = await db.organization.create({ data: {
      name: "Evidence A", slug: `evidence-auth-a-${nonce}`,
      memberships: { create: { userId: owner.id, role: "OWNER" } },
    } });
    const b = await db.organization.create({ data: {
      name: "Evidence B", slug: `evidence-auth-b-${nonce}`,
      memberships: { create: { userId: owner.id, role: "AUDITOR" } },
    } });
    try {
      for (const [organizationId, scope] of [[a.id, "a.example.test"], [b.id, "b.example.test"]]) {
        await db.securityEvidence.create({ data: {
          organizationId, source: "DOMAIN", domain: "EMAIL",
          controlId: "DMARC", scope, state: "OBSERVED",
          observedAt: new Date(), details: {},
        } });
      }
      expect(await listOrganizationEvidenceForUser(a.id, stranger.id)).toBeNull();
      expect(await listOrganizationEvidenceForUser(b.id, stranger.id)).toBeNull();
      const evidenceA = await listOrganizationEvidenceForUser(a.id, owner.id);
      const evidenceB = await listOrganizationEvidenceForUser(b.id, owner.id);
      expect(evidenceA).toMatchObject([{ organizationId: a.id, scope: "a.example.test" }]);
      expect(evidenceB).toMatchObject([{ organizationId: b.id, scope: "b.example.test" }]);
      expect(await listOrganizationEvidenceForUser("missing-org", owner.id)).toBeNull();
    } finally {
      await db.organization.deleteMany({ where: { id: { in: [a.id, b.id] } } });
      await db.user.deleteMany({ where: { id: { in: [owner.id, stranger.id] } } });
    }
  });
});
