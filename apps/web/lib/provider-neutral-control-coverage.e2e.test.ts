import { describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { getOrganizationControlCoverageForUser } from "./provider-neutral-evidence";

describe("authorized required-control coverage", () => {
  it("isolates tenant observations and counts each required control exactly once", async () => {
    const nonce = crypto.randomUUID();
    const owner = await db.user.create({ data: { name: "Owner", email: `control-owner-${nonce}@example.test` } });
    const stranger = await db.user.create({ data: { name: "Stranger", email: `control-stranger-${nonce}@example.test` } });
    const org = await db.organization.create({
      data: { name: "Required controls", slug: `control-org-${nonce}`, memberships: { create: { userId: owner.id, role: "OWNER" } } },
    });
    const other = await db.organization.create({ data: { name: "Other controls", slug: `control-other-${nonce}` } });
    const expected = [{ domain: "EMAIL" as const, controlId: "SPF" }, { domain: "EMAIL" as const, controlId: "DMARC" }];
    try {
      await db.securityEvidence.create({ data: {
        organizationId: org.id, source: "DOMAIN", domain: "EMAIL", controlId: "SPF",
        scope: "primary.test", state: "OBSERVED", observedAt: new Date(), details: {},
      } });
      await db.securityEvidence.create({ data: {
        organizationId: org.id, source: "BASELINE", domain: "EMAIL", controlId: "DMARC",
        scope: "primary.test", state: "DECLARED", observedAt: null, details: {},
      } });
      await db.securityEvidence.create({ data: {
        organizationId: other.id, source: "DOMAIN", domain: "EMAIL", controlId: "DMARC",
        scope: "other.test", state: "OBSERVED", observedAt: new Date(), details: {},
      } });
      expect(await getOrganizationControlCoverageForUser(org.id, stranger.id, expected)).toBeNull();
      expect(await getOrganizationControlCoverageForUser(other.id, owner.id, expected)).toBeNull();
      expect(await getOrganizationControlCoverageForUser(org.id, owner.id, expected)).toEqual({
        coverage: "PARTIAL", assessedCount: 1, expectedCount: 2,
        missingControls: [{ domain: "EMAIL", controlId: "DMARC" }],
      });
      expect((await getOrganizationControlCoverageForUser(org.id, owner.id, [...expected, expected[0]!]))?.expectedCount).toBe(2);
      expect((await getOrganizationControlCoverageForUser(org.id, owner.id, []))?.coverage).toBe("UNASSESSED");
      expect(await getOrganizationControlCoverageForUser(org.id, owner.id, [
        { domain: "EMAIL", controlId: "SPF", scope: "primary.test" },
        { domain: "EMAIL", controlId: "SPF", scope: "secondary.test" },
      ])).toEqual({
        coverage: "PARTIAL", assessedCount: 1, expectedCount: 2,
        missingControls: [{ domain: "EMAIL", controlId: "SPF", scope: "secondary.test" }],
      });
    } finally {
      await db.organization.deleteMany({ where: { id: { in: [org.id, other.id] } } });
      await db.user.deleteMany({ where: { id: { in: [owner.id, stranger.id] } } });
    }
  });
});
