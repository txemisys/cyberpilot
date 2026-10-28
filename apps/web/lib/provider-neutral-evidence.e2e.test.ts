import { describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";

describe("provider-neutral evidence persistence", () => {
  it("isolates controls by organization and permits matching control IDs", async () => {
    const nonce = crypto.randomUUID();
    const a = await db.organization.create({ data: { name: "Evidence Org A", slug: `evidence-a-${nonce}` } });
    const b = await db.organization.create({ data: { name: "Evidence Org B", slug: `evidence-b-${nonce}` } });
    try {
      for (const organizationId of [a.id, b.id]) {
        await db.securityEvidence.create({
          data: {
            organizationId, source: "BASELINE", domain: "BACKUP",
            controlId: "BACKUP_RESTORE_TEST", state: "DECLARED",
            scope: "company", details: { answer: "yes" },
          },
        });
      }

      const scoped = await db.securityEvidence.findMany({
        where: { organizationId: a.id, domain: "BACKUP" },
      });
      expect(scoped).toHaveLength(1);
      expect(scoped[0].organizationId).toBe(a.id);
      expect(scoped[0].observedAt).toBeNull();
      expect(scoped[0].state).toBe("DECLARED");

      await expect(db.securityEvidence.create({
        data: {
          organizationId: a.id, source: "BASELINE", domain: "BACKUP",
          controlId: "BACKUP_RESTORE_TEST", state: "DECLARED",
          scope: "company", details: {},
        },
      })).rejects.toMatchObject({ code: "P2002" });

      expect(await db.securityEvidence.count({ where: { organizationId: b.id } })).toBe(1);
    } finally {
      await db.organization.delete({ where: { id: a.id } });
      await db.organization.delete({ where: { id: b.id } });
    }
  });

  it("cascades organization deletion without affecting other tenants", async () => {
    const nonce = crypto.randomUUID();
    const a = await db.organization.create({ data: { name: "Evidence Cascade A", slug: `evidence-cascade-a-${nonce}` } });
    const b = await db.organization.create({ data: { name: "Evidence Cascade B", slug: `evidence-cascade-b-${nonce}` } });
    try {
      for (const organizationId of [a.id, b.id]) {
        await db.securityEvidence.create({
          data: { organizationId, source: "DOMAIN", domain: "EMAIL", controlId: "DMARC", state: "OBSERVED", scope: "example.test", observedAt: new Date(), details: {} },
        });
      }
      await db.organization.delete({ where: { id: a.id } });
      expect(await db.securityEvidence.count({ where: { organizationId: a.id } })).toBe(0);
      expect(await db.securityEvidence.count({ where: { organizationId: b.id } })).toBe(1);
    } finally {
      await db.organization.deleteMany({ where: { id: { in: [a.id, b.id] } } });
    }
  });
});
