import { describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { getOrganizationEvidenceCoverageForUser } from "./provider-neutral-evidence";

describe("authorized multi-source coverage", () => {
  it("keeps declared evidence unassessed, isolates tenants, and requires observed timestamps", async () => {
    const nonce = crypto.randomUUID();
    const owner = await db.user.create({ data: { name: "Coverage Owner", email: `coverage-owner-${nonce}@example.test` } });
    const stranger = await db.user.create({ data: { name: "Coverage Stranger", email: `coverage-stranger-${nonce}@example.test` } });
    const org = await db.organization.create({
      data: { name: "Coverage Lab", slug: `coverage-lab-${nonce}`, memberships: { create: { userId: owner.id, role: "OWNER" } } },
    });
    const other = await db.organization.create({ data: { name: "Other Coverage", slug: `coverage-other-${nonce}` } });
    const expected = ["EMAIL", "BACKUP"] as const;
    try {
      await db.securityEvidence.create({
        data: { organizationId: org.id, source: "BASELINE", domain: "BACKUP", controlId: "RESTORE", scope: "company", state: "DECLARED", details: { answer: "yes" } },
      });
      await db.securityEvidence.create({
        data: { organizationId: other.id, source: "DOMAIN", domain: "EMAIL", controlId: "DMARC", scope: "other.test", state: "OBSERVED", observedAt: new Date(), details: {} },
      });
      expect(await getOrganizationEvidenceCoverageForUser(org.id, stranger.id, expected)).toBeNull();
      expect(await getOrganizationEvidenceCoverageForUser(org.id, owner.id, expected)).toEqual({
        coverage: "UNASSESSED", assessedDomains: [], unassessedDomains: ["EMAIL", "BACKUP"],
      });
      await db.securityEvidence.create({
        data: { organizationId: org.id, source: "DOMAIN", domain: "EMAIL", controlId: "DMARC", scope: "lab.test", state: "OBSERVED", observedAt: new Date(), details: {} },
      });
      expect(await getOrganizationEvidenceCoverageForUser(org.id, owner.id, expected)).toEqual({
        coverage: "PARTIAL", assessedDomains: ["EMAIL"], unassessedDomains: ["BACKUP"],
      });
      await db.securityEvidence.updateMany({
        where: { organizationId: org.id, domain: "BACKUP" },
        data: { state: "OBSERVED", observedAt: null },
      });
      expect((await getOrganizationEvidenceCoverageForUser(org.id, owner.id, expected))?.coverage).toBe("PARTIAL");
      await db.securityEvidence.updateMany({
        where: { organizationId: org.id, domain: "BACKUP" },
        data: { state: "OBSERVED", observedAt: new Date() },
      });
      expect((await getOrganizationEvidenceCoverageForUser(org.id, owner.id, expected))?.coverage).toBe("COMPLETE");
    } finally {
      await db.organization.deleteMany({ where: { id: { in: [org.id, other.id] } } });
      await db.user.deleteMany({ where: { id: { in: [owner.id, stranger.id] } } });
    }
  });
});
