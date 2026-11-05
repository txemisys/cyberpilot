import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory, retireAssetInventory } from "./assets-inventory-service";
import { readAssetComparison } from "./assets-inventory-comparison";
import { inspectAssetRetention, purgeAssetInventory } from "./assets-inventory-retention";
import type { AssetScope } from "./assets-inventory-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "asset longitudinal and irreversible purge PostgreSQL boundaries", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const organizationId = "asset-long-" + suffix;
    const otherId = "asset-long-other-" + suffix;
    const adminId = "asset-long-admin-" + suffix;
    const memberId = "asset-long-member-" + suffix;
    const foreignId = "asset-long-foreign-" + suffix;
    const admin: AssetScope = {
      organizationId, userId: adminId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: otherId, userId: foreignId, role: "ADMIN",
    };
    const now = new Date("2026-11-05T12:00:00.000Z");
    const header = "asset_id,hostname,owner,platform,os_name,os_version," +
      "software_name,software_version,observed_at\n";
    const earlier = header +
      "asset-a,host-a,,WINDOWS,Windows 10,21H2,Browser,1.2,2026-01-01T00:00:00.000Z\n" +
      "asset-b,host-b,,LINUX,Ubuntu,20.04,Database,2.0,2026-01-01T00:00:00.000Z\n";
    const later = header +
      "asset-a,host-a,,WINDOWS,Windows 11,23H2,Browser,2.0,2026-10-01T00:00:00.000Z\n" +
      "asset-c,host-c,,MACOS,macOS,14.5,Editor,4.1,2026-10-01T00:00:00.000Z\n";
    let previousImportId = "";
    let currentImportId = "";
    let priorDigest = "";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Asset longitudinal admin",
          email: "asset-long-admin-" + suffix + "@example.invalid" },
        { id: memberId, name: "Asset longitudinal member",
          email: "asset-long-member-" + suffix + "@example.invalid" },
        { id: foreignId, name: "Asset longitudinal foreign",
          email: "asset-long-foreign-" + suffix + "@example.invalid" },
      ]});
      await db.organization.createMany({ data: [
        { id: organizationId, name: "Asset longitudinal organization",
          slug: "asset-long-" + suffix },
        { id: otherId, name: "Other asset longitudinal organization",
          slug: "asset-long-other-" + suffix },
      ]});
      await db.membership.createMany({ data: [
        { organizationId, userId: adminId, role: "ADMIN" },
        { organizationId, userId: memberId, role: "MEMBER" },
        { organizationId: otherId, userId: foreignId, role: "ADMIN" },
      ]});
      const prior = await importAssetInventory(admin, {
        sourceLabel: "First declared export",
        idempotencyKey: "asset-long-prior-" + suffix,
        csv: earlier, dryRun: false,
      }, new Date("2026-01-10T00:00:00.000Z"));
      previousImportId = prior.importId!;
      const next = await importAssetInventory(admin, {
        sourceLabel: "Second declared export",
        idempotencyKey: "asset-long-current-" + suffix,
        csv: later, dryRun: false,
      }, now);
      currentImportId = next.importId!;
      const old = await db.assetInventoryImport.findUniqueOrThrow({
        where: { id: previousImportId },
      });
      priorDigest = old.payloadDigest;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, otherId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, foreignId] } },
      });
    });
    it("compares two scoped stored snapshots with conservative absence", async () => {
      const result = await readAssetComparison(member, {
        previousImportId, currentImportId,
      }, now);
      expect(result.summary).toMatchObject({
        inspectedPrevious: 2,
        inspectedCurrent: 2,
        newAssets: 1,
        missingFromExport: 1,
        versionChanges: 1,
        osChanges: 1,
      });
      expect(result.coverage).toBe("DECLARED_SCOPE_UNKNOWN");
      expect(result.rows.some(x =>
        x.category === "MISSING_FROM_EXPORT" &&
        x.explanations.join(" ").includes("not proof"))).toBe(true);
    });
    it("rejects foreign snapshot IDs without leaking rows", async () => {
      await expect(readAssetComparison(outsider, {
        previousImportId, currentImportId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
      await expect(readAssetComparison(admin, {
        previousImportId, currentImportId: "foreign-import-12345",
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("prevents scope-free retention queries", async () => {
      await expect(inspectAssetRetention(member, {}, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      const report = await inspectAssetRetention(admin, {
        minimumRetiredDays: 30,
      }, now);
      expect(report.total).toBe(2);
      expect(report.candidates.every(x => !x.eligible)).toBe(true);
    });
    it("requires retired state before any purge", async () => {
      await expect(purgeAssetInventory(admin, {
        importId: previousImportId,
        expectedDigest: priorDigest,
        confirmImportId: previousImportId, confirmPurge: true,
        minimumRetiredDays: 1,
        reason: "Synthetic snapshot removed after test retirement.",
        idempotencyKey: "asset-long-purge-" + suffix,
        dryRun: false,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("retires the chosen snapshot but leaves the newer one visible", async () => {
      const retirement = new Date("2026-10-01T00:00:00.000Z");
      await retireAssetInventory(admin, {
        importId: previousImportId,
        expectedState: "COMMITTED",
        reason: "Superseded by the newer synthetic export.",
      }, retirement);
      await db.assetInventoryImport.update({
        where: { id: previousImportId },
        data: { createdAt: new Date("2026-01-10T00:00:00.000Z") },
      });
      const retained = await inspectAssetRetention(admin, {
        minimumRetiredDays: 30, maximumCandidateAgeDays: 30,
      }, now);
      expect(retained.candidates.some(row =>
        row.importId === previousImportId && row.eligible)).toBe(true);
      expect(await db.assetInventoryDevice.count({
        where: { organizationId, importId: currentImportId },
      })).toBe(2);
    });
    it("previews a purge without deleting the snapshot or its rows", async () => {
      const before = await db.assetInventoryDevice.count({
        where: { importId: previousImportId, organizationId },
      });
      const report = await purgeAssetInventory(admin, {
        importId: previousImportId,
        expectedDigest: priorDigest,
        confirmImportId: previousImportId, confirmPurge: true,
        minimumRetiredDays: 30,
        reason: "Remove obsolete synthetic data after retention.",
        idempotencyKey: "asset-long-purge-" + suffix,
        dryRun: true,
      }, now);
      expect(report.status).toBe("PREVIEW");
      expect(report.devicesAffected).toBe(before);
      expect(await db.assetInventoryImport.count({
        where: { id: previousImportId, organizationId },
      })).toBe(1);
    });
    it("deletes only the retired snapshot, retains audit and rejects cross-tenant purge", async () => {
      const command = {
        importId: previousImportId,
        expectedDigest: priorDigest,
        confirmImportId: previousImportId, confirmPurge: true,
        minimumRetiredDays: 30,
        reason: "Remove obsolete synthetic data after retention.",
        idempotencyKey: "asset-long-purge-" + suffix,
        dryRun: false,
      };
      await expect(purgeAssetInventory(outsider, command, now))
        .rejects.toMatchObject({ code: "MISSING" });
      const result = await purgeAssetInventory(admin, command, now);
      expect(result.status).toBe("PURGED");
      expect(result.devicesAffected).toBe(2);
      expect(await db.assetInventoryImport.count({
        where: { id: previousImportId },
      })).toBe(0);
      expect(await db.assetInventoryDevice.count({
        where: { importId: previousImportId },
      })).toBe(0);
      expect(await db.assetInventoryDevice.count({
        where: { importId: currentImportId, organizationId },
      })).toBe(2);
      const audits = await db.auditEvent.findMany({
        where: {
          organizationId,
          action: "assets.csv.import.purged",
          resourceId: previousImportId,
        },
      });
      expect(audits).toHaveLength(1);
      expect(JSON.stringify(audits)).not.toContain("host-a");
    });
    it("replays a successful purge without deleting again", async () => {
      const result = await purgeAssetInventory(admin, {
        importId: previousImportId,
        expectedDigest: priorDigest,
        confirmImportId: previousImportId, confirmPurge: true,
        minimumRetiredDays: 30,
        reason: "Remove obsolete synthetic data after retention.",
        idempotencyKey: "asset-long-purge-" + suffix,
        dryRun: false,
      }, now);
      expect(result.status).toBe("REPLAYED");
      expect(result.replayed).toBe(true);
      expect(await db.auditEvent.count({
        where: { organizationId, action: "assets.csv.import.purged" },
      })).toBe(1);
    });
  },
);
