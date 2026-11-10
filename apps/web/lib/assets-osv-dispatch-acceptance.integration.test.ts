import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import { createOsvSchedule } from "./assets-osv-renewal-schedules";
import { inspectOsvDispatchPreflight } from "./assets-osv-dispatch-preflight";
import { inspectOsvForensicTimeline } from "./assets-osv-dispatch-forensics";
import type { AssetScope } from "./assets-inventory-service";

const now = new Date("2026-11-10T12:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "Tenant-scoped dispatch preflight and forensic PostgreSQL acceptance", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 15);
    const org = "osv-accept-org-" + token;
    const foreign = "osv-accept-other-" + token;
    const adminId = "osv-accept-admin-" + token;
    const memberId = "osv-accept-reader-" + token;
    const outsiderId = "osv-accept-other-user-" + token;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId: org, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: outsiderId, role: "ADMIN",
    };
    let scheduleId = "";
    let importId = "";
    let inspectionId = "";
    const oldFlag = process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED;
    const oldKeys = process.env.CYBERPILOT_OSV_DISPATCH_KEYS;
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Acceptance admin",
          email: "accept-admin-" + token + "@example.invalid" },
        { id: memberId, name: "Acceptance reader",
          email: "accept-reader-" + token + "@example.invalid" },
        { id: outsiderId, name: "Acceptance outsider",
          email: "accept-other-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "OSV local acceptance",
          slug: "osv-accept-" + token },
        { id: foreign, name: "OSV foreign acceptance",
          slug: "osv-accept-other-" + token },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: memberId, role: "MEMBER" },
        { organizationId: foreign, userId: outsiderId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        sourceLabel: "Forensic local fixture",
        idempotencyKey: "osv-accept-import-" + token,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "fixture-1,host-1,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
        ].join("\n") + "\n",
      }, new Date("2026-11-01T12:00:00.000Z"));
      importId = imported.importId!;
      const inspection = await db.assetOsvInspection.create({ data: {
        organizationId: org, inventoryImportId: importId,
        requestKey: "osv-accept-prior-" + token,
        requestDigest: "a".repeat(64),
        reportDigest: "b".repeat(64),
        status: "COMPLETE", provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 0, completedCount: 0,
        possibleCount: 0, providerOnlyCount: 0,
        completedAt: new Date("2026-11-01T12:00:00.000Z"),
        report: { schema: "cyberpilot.assets.osv.test.v1" },
      } });
      inspectionId = inspection.id;
      const schedule = await createOsvSchedule(admin, {
        name: "Forensic OSV acceptance fixture",
        inventoryImportId: importId,
        sourceInspectionId: inspectionId,
        cadenceMinutes: 60,
        inspection: {
          importId, dryRun: true,
          packageBindings: [{
            inventoryProduct: "Example Package",
            ecosystem: "npm", packageName: "example-package",
          }],
          limitPackages: 5, maxPagesPerPackage: 2,
          maxRecordsPerPackage: 50, maxAgeMinutes: 60,
        },
        policy: {
          freshnessMinutes: 60, minimumRetryMinutes: 60,
          maximumPackagesPerRun: 5,
          maximumQueriesPerDay: 200,
          maximumInspectionsPerDay: 20,
          historyWindowDays: 90, includeIncomplete: true,
        },
        allowNewPackages: false, allowIncompleteInventory: false,
      }, new Date("2026-11-10T10:00:00.000Z"));
      scheduleId = schedule.id;
      process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED = "false";
      delete process.env.CYBERPILOT_OSV_DISPATCH_KEYS;
      await db.assetOsvRenewalRun.create({ data: {
        organizationId: org, scheduleId,
        slotAt: new Date("2026-11-10T11:00:00.000Z"),
        claimedAt: new Date("2026-11-10T11:01:00.000Z"),
        claimExpiresAt: new Date("2026-11-10T11:31:00.000Z"),
        state: "CLAIMED", commandDigest: "c".repeat(64),
        claimToken: "d".repeat(64),
      } });
      await db.assetOsvDispatchNonce.create({ data: {
        organizationId: org, scheduleId,
        keyId: "synthetic-accept-key-12345",
        acceptedAt: new Date("2026-11-10T11:00:50.000Z"),
        expiresAt: new Date("2026-11-10T11:02:50.000Z"),
        requestDigest: "e".repeat(64),
        nonceDigest: "f".repeat(64),
      } });
    });
    afterAll(async () => {
      if (oldFlag === undefined)
        delete process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED;
      else process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED = oldFlag;
      if (oldKeys === undefined)
        delete process.env.CYBERPILOT_OSV_DISPATCH_KEYS;
      else process.env.CYBERPILOT_OSV_DISPATCH_KEYS = oldKeys;
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, outsiderId] } },
      });
    });
    it("prohibits diagnostic access for members", async () => {
      await expect(inspectOsvDispatchPreflight(member, {}, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectOsvForensicTimeline(member, {}, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("returns no cross-tenant evidence or schedules", async () => {
      const preflight = await inspectOsvDispatchPreflight(outsider,
        {}, now);
      expect(preflight.totalSchedules).toBe(0);
      const forensic = await inspectOsvForensicTimeline(outsider,
        {}, now);
      expect(forensic.nodes).toEqual([]);
      expect(forensic.organizationId).toBe(foreign);
    });
    it("requires an existing in-organization schedule for targeted preflight", async () => {
      await expect(inspectOsvDispatchPreflight(outsider, {
        scheduleId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("reports disabled service, consent and open claim without network", async () => {
      const result = await inspectOsvDispatchPreflight(admin, {
        scheduleId,
      }, now);
      expect(result).toMatchObject({
        organizationId: org, totalSchedules: 1,
        manuallyReviewableSchedules: 0,
        keysEnabled: false, noncesConsumed: 0,
        outboundRequests: 0, cronInstalled: false,
      });
      expect(result.schedules[0]!.checks.some(row =>
        row.id === "NO_OPEN_CLAIMS" && row.level === "BLOCK"))
        .toBe(true);
    });
    it("reconstructs accepted signature and claim as heuristic evidence", async () => {
      const result = await inspectOsvForensicTimeline(admin, {
        scheduleId, lookbackHours: 24,
        includeQuota: false, includeInspections: false,
        includeAudit: false,
      }, now);
      expect(result.complete).toBe(true);
      expect(result.collectionCounts.signatures).toBe(1);
      expect(result.collectionCounts.runs).toBe(1);
      expect(result.edges.some(edge =>
        edge.confidence === "HEURISTIC")).toBe(true);
      expect(result.networkRequestsMade).toBe(0);
    });
    it("does not mutate runs, nonces or schedule state during forensics", async () => {
      const [beforeRun, beforeNonce] = await Promise.all([
        db.assetOsvRenewalRun.count({
          where: { organizationId: org, scheduleId },
        }),
        db.assetOsvDispatchNonce.count({
          where: { organizationId: org, scheduleId },
        }),
      ]);
      await inspectOsvForensicTimeline(admin, {
        scheduleId,
      }, now);
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org, scheduleId },
      })).toBe(beforeRun);
      expect(await db.assetOsvDispatchNonce.count({
        where: { organizationId: org, scheduleId },
      })).toBe(beforeNonce);
    });
  },
);
