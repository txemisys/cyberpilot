import { describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { upsertDeclaredOrganizationEvidenceForUser } from "./provider-neutral-evidence";

describe("authorized baseline evidence writes", () => {
  it("allows owner/admin, blocks members and outsiders, and audits without treating declarations as observations", async () => {
    const nonce = crypto.randomUUID();
    const users = await Promise.all(["OWNER", "ADMIN", "MEMBER", "OUTSIDER"].map(async (role) =>
      db.user.create({ data: { name: role, email: `evidence-write-${role}-${nonce}@example.test` } }),
    ));
    const [owner, admin, member, outsider] = users;
    if (!owner || !admin || !member || !outsider) throw new Error("Missing test users");
    const org = await db.organization.create({
      data: {
        name: "Evidence write test", slug: `evidence-write-${nonce}`,
        memberships: {
          create: [
            { userId: owner.id, role: "OWNER" },
            { userId: admin.id, role: "ADMIN" },
            { userId: member.id, role: "MEMBER" },
          ],
        },
      },
    });
    const other = await db.organization.create({ data: { name: "Other", slug: `evidence-write-other-${nonce}` } });
    const payload = { domain: "BACKUP" as const, controlId: "RESTORE_TEST", scope: "company", details: { answer: "yes" } };
    try {
      expect(await upsertDeclaredOrganizationEvidenceForUser(org.id, member.id, payload)).toBeNull();
      expect(await upsertDeclaredOrganizationEvidenceForUser(org.id, outsider.id, payload)).toBeNull();
      expect(await upsertDeclaredOrganizationEvidenceForUser(other.id, owner.id, payload)).toBeNull();
      expect(await db.securityEvidence.count({ where: { organizationId: org.id } })).toBe(0);
      expect(await db.auditEvent.count({ where: { organizationId: org.id, action: "evidence.baseline.declared_upsert" } })).toBe(0);

      const first = await upsertDeclaredOrganizationEvidenceForUser(org.id, owner.id, payload);
      const second = await upsertDeclaredOrganizationEvidenceForUser(org.id, admin.id, { ...payload, details: { answer: "no" } });
      expect(first).toMatchObject({ organizationId: org.id, source: "BASELINE", state: "DECLARED", observedAt: null });
      expect(second?.id).toBe(first?.id);
      expect(await db.securityEvidence.count({ where: { organizationId: org.id } })).toBe(1);
      expect(await db.securityEvidence.count({ where: { organizationId: other.id } })).toBe(0);
      const stored = await db.securityEvidence.findFirstOrThrow({ where: { organizationId: org.id } });
      expect(stored.details).toEqual({ answer: "no" });
      expect(await db.auditEvent.count({ where: { organizationId: org.id, action: "evidence.baseline.declared_upsert" } })).toBe(2);
      expect(await upsertDeclaredOrganizationEvidenceForUser(org.id, owner.id, { ...payload, scope: "  " })).toBeNull();
    } finally {
      await db.organization.deleteMany({ where: { id: { in: [org.id, other.id] } } });
      await db.user.deleteMany({ where: { id: { in: users.map((user) => user.id) } } });
    }
  });
});
