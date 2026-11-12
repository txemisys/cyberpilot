import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import { inspectOsvInventoryCandidates } from "./assets-osv-service";
import type { AssetScope } from "./assets-inventory-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "Assets OSV correlation persisted inventory boundaries", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 16);
    const orgId = "osv-org-" + nonce;
    const otherId = "osv-other-" + nonce;
    const adminId = "osv-admin-" + nonce;
    const memberId = "osv-member-" + nonce;
    const outsiderId = "osv-outside-" + nonce;
    const admin: AssetScope = {
      organizationId: orgId, userId: adminId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId: orgId, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: otherId, userId: outsiderId, role: "ADMIN",
    };
    const now = new Date("2026-11-05T12:00:00.000Z");
    const csv = [
      "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
      "asset-001,host-a,,LINUX,Ubuntu,22.04,Example Package,1.2.3,2026-11-04T12:00:00.000Z",
      "asset-002,host-b,,LINUX,Ubuntu,22.04,Example Package,latest,2026-11-04T12:00:00.000Z",
      "asset-003,host-c,,WINDOWS,Windows 11,23H2,Different Software,3.0.0,2026-11-04T12:00:00.000Z",
    ].join("\n") + "\n";
    const feed = {
      sourceLabel: "Synthetic test OSV export",
      sourceVersion: "example-v1",
      retrievedAt: "2026-11-04T12:00:00Z",
      records: [
        {
          id: "CVE-2026-99991",
          modified: "2026-11-04T12:00:00Z",
          affected: [{
            package: { ecosystem: "npm", name: "example-package" },
            versions: ["1.2.3"],
          }],
        },
        {
          id: "CVE-2026-99992",
          modified: "2026-11-04T12:00:00Z",
          affected: [{
            package: { ecosystem: "npm", name: "example-package" },
            ranges: [{
              type: "SEMVER",
              events: [{ introduced: "0" }, { fixed: "1.3.0" }],
            }],
          }],
        },
      ],
    };
    const packageBindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }];
    let importId = "";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "OSV admin",
          email: "osv-admin-" + nonce + "@example.invalid" },
        { id: memberId, name: "OSV member",
          email: "osv-member-" + nonce + "@example.invalid" },
        { id: outsiderId, name: "OSV outsider",
          email: "osv-outsider-" + nonce + "@example.invalid" },
      ]});
      await db.organization.createMany({ data: [
        { id: orgId, name: "OSV assets organization",
          slug: "osv-assets-" + nonce },
        { id: otherId, name: "OSV foreign organization",
          slug: "osv-foreign-" + nonce },
      ]});
      await db.membership.createMany({ data: [
        { organizationId: orgId, userId: adminId, role: "ADMIN" },
        { organizationId: orgId, userId: memberId, role: "MEMBER" },
        { organizationId: otherId, userId: outsiderId, role: "ADMIN" },
      ]});
      const imported = await importAssetInventory(admin, {
        csv, sourceLabel: "Synthetic package export",
        idempotencyKey: "osv-import-" + nonce, dryRun: false,
      }, now);
      importId = imported.importId!;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [orgId, otherId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, outsiderId] } },
      });
    });
    it("inspects persisted rows and reports exact candidates with unknowns", async () => {
      const report = await inspectOsvInventoryCandidates(member, {
        importId, feed, packageBindings,
      }, now);
      expect(report.importState).toBe("COMMITTED");
      expect(report.report.totalRows).toBe(3);
      expect(report.report.summary.possibleAssociations).toBe(1);
      expect(report.report.summary.unmappedRows).toBe(1);
      expect(report.report.summary.unknownVersions).toBe(1);
      expect(report.report.summary.unresolvedRanges).toBe(2);
      expect(report.report.candidates.find(row => row.externalId === "asset-001")
        ?.possibleAdvisoryIds).toEqual(["CVE-2026-99991"]);
      expect(report.report.digest).toMatch(/^[0-9a-f]{64}$/);
    });
    it("rejects cross-tenant snapshot access without leaking existence", async () => {
      await expect(inspectOsvInventoryCandidates(outsider, {
        importId, feed, packageBindings,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("paginates and does not mark a page globally complete", async () => {
      const report = await inspectOsvInventoryCandidates(admin, {
        importId, feed, packageBindings, limit: 1, offset: 0,
      }, now);
      expect(report.report.candidates).toHaveLength(1);
      expect(report.report.summary.totalRows).toBe(3);
      expect(report.report.hasMore).toBe(true);
      expect(report.report.complete).toBe(false);
    });
    it("does not persist OSV records or mutate the asset snapshot", async () => {
      const before = await db.assetInventoryImport.findUniqueOrThrow({
        where: { id: importId },
      });
      const recordsBefore = await db.assetInventoryDevice.findMany({
        where: { organizationId: orgId, importId },
      });
      await inspectOsvInventoryCandidates(admin, {
        importId, feed, packageBindings,
      }, now);
      const after = await db.assetInventoryImport.findUniqueOrThrow({
        where: { id: importId },
      });
      const recordsAfter = await db.assetInventoryDevice.findMany({
        where: { organizationId: orgId, importId },
      });
      expect(after.payloadDigest).toBe(before.payloadDigest);
      expect(after.state).toBe(before.state);
      expect(recordsAfter).toEqual(recordsBefore);
      expect(await db.auditEvent.count({
        where: { organizationId: orgId, action: "assets.osv.candidates.mutated" },
      })).toBe(0);
    });
  },
);
