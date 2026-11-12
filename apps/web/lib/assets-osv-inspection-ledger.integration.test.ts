import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory, retireAssetInventory } from "./assets-inventory-service";
import {
  persistOsvInspection, listOsvInspections,
  readOsvInspection, parseOsvLedgerCommand,
} from "./assets-osv-inspection-ledger";
import type { AssetScope } from "./assets-inventory-service";
import type { LiveOsvQueryResult } from "./assets-osv-official-client";
const now = new Date("2026-11-05T13:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV immutable inspection history PostgreSQL", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "osv-ledger-" + suffix;
    const foreign = "osv-ledger-foreign-" + suffix;
    const adminId = "osv-ledger-admin-" + suffix;
    const readerId = "osv-ledger-reader-" + suffix;
    const strangerId = "osv-ledger-other-" + suffix;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: readerId, role: "MEMBER",
    };
    const stranger: AssetScope = {
      organizationId: foreign, userId: strangerId, role: "ADMIN",
    };
    const bindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }];
    const csv = [
      "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
      "device-a,host-a,,LINUX,Ubuntu,22.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
      "device-b,host-b,,LINUX,Ubuntu,22.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
    ].join("\n") + "\n";
    const query = vi.fn(async () => ({
      schema: "cyberpilot.assets.osv.live.query.v1" as const,
      endpoint: "https://api.osv.dev" as const,
      package: {
        ecosystem: "npm", name: "example-package",
        version: "1.2.3",
      },
      checkedAt: now.toISOString(),
      provider: "OSV_DEV_API" as const,
      transport: "HTTPS_FIXED_ENDPOINT" as const,
      status: "COMPLETE" as const,
      queriedPages: 1, responseBytes: 150,
      vulnerabilities: [{
        id: "GHSA-abcd-1234-5678",
        modified: now.toISOString(),
        withdrawn: null, aliases: ["CVE-2026-12345"],
        exactVersionListed: true, packageIdentityListed: true,
        rangesPresent: false, fingerprint: "a".repeat(64),
      }],
      providerReportedCount: 1, exactEnumeratedCount: 1,
      nonEnumeratedCount: 0, withdrawnCount: 0,
      warnings: [], digest: "b".repeat(64),
    } satisfies LiveOsvQueryResult));
    let importId = "";
    let inspectionId = "";
    const requestKey = "ledger-key-" + suffix;
    const args = () => ({
      requestKey,
      inspection: {
        importId, packageBindings: bindings,
        limitPackages: 10, maxPagesPerPackage: 2,
        maxRecordsPerPackage: 50, maxAgeMinutes: 60,
        dryRun: false,
      },
    });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "OSV ledger admin",
          email: "osv-ledger-admin-" + suffix + "@example.invalid" },
        { id: readerId, name: "OSV ledger reader",
          email: "osv-ledger-reader-" + suffix + "@example.invalid" },
        { id: strangerId, name: "OSV ledger stranger",
          email: "osv-ledger-other-" + suffix + "@example.invalid" },
      ]});
      await db.organization.createMany({ data: [
        { id: org, name: "OSV ledger test",
          slug: "osv-ledger-" + suffix },
        { id: foreign, name: "OSV ledger foreign test",
          slug: "osv-ledger-foreign-" + suffix },
      ]});
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: readerId, role: "MEMBER" },
        { organizationId: foreign, userId: strangerId, role: "ADMIN" },
      ]});
      const imported = await importAssetInventory(admin, {
        csv, sourceLabel: "OSV ledger fixture",
        idempotencyKey: "osv-ledger-import-" + suffix,
        dryRun: false,
      }, now);
      importId = imported.importId!;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, readerId, strangerId] } },
      });
    });
    it("prevents non-administrative users from starting provider queries", async () => {
      query.mockClear();
      await expect(persistOsvInspection(reader, args(), {
        query, now: () => now,
      })).rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(query).not.toHaveBeenCalled();
    });
    it("prevents cross-tenant requests before contacting OSV", async () => {
      query.mockClear();
      await expect(persistOsvInspection(stranger, args(), {
        query, now: () => now,
      })).rejects.toMatchObject({ code: "MISSING" });
      expect(query).not.toHaveBeenCalled();
    });
    it("persists provider inspection, normalized queries and audit atomically", async () => {
      query.mockClear();
      const result = await persistOsvInspection(admin, args(), {
        query, now: () => now,
      });
      inspectionId = result.inspectionId;
      expect(result.replayed).toBe(false);
      expect(result.queryCount).toBe(1);
      expect(query).toHaveBeenCalledTimes(1);
      const stored = await db.assetOsvInspection.findUniqueOrThrow({
        where: { id: inspectionId },
        include: { queries: true },
      });
      expect(stored.queries).toHaveLength(1);
      expect(stored.queries[0]?.possibleIds).toEqual(["GHSA-abcd-1234-5678"]);
      expect(stored.reportDigest).toBe(result.reportDigest);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org,
          action: "assets.osv.inspection.committed",
          resourceId: inspectionId,
        },
      })).toBe(1);
    });
    it("replays the original persisted report with zero extra provider queries", async () => {
      query.mockClear();
      const replay = await persistOsvInspection(admin, args(), {
        query, now: () => now,
      });
      expect(replay.replayed).toBe(true);
      expect(replay.inspectionId).toBe(inspectionId);
      expect(query).not.toHaveBeenCalled();
      expect(await db.assetOsvInspection.count({
        where: { organizationId: org },
      })).toBe(1);
      expect(await db.assetOsvQueryRecord.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("rejects reused idempotency keys with modified package parameters", async () => {
      query.mockClear();
      const modified = {
        ...args(),
        inspection: {
          ...args().inspection, maxAgeMinutes: 120,
        },
      };
      await expect(persistOsvInspection(admin, modified, {
        query, now: () => now,
      })).rejects.toMatchObject({ code: "CONFLICT" });
      expect(query).not.toHaveBeenCalled();
    });
    it("allows readers to inspect recorded results but not foreign organizations", async () => {
      const list = await listOsvInspections(reader, {});
      expect(list.total).toBe(1);
      expect(list.inspections[0]?.id).toBe(inspectionId);
      const detail = await readOsvInspection(reader, {
        inspectionId,
      });
      expect(detail.report.status).toBe("COMPLETE");
      expect(detail.recordedQueries).toHaveLength(1);
      expect(detail.report.reportDigest).toBe(detail.persistedReportDigest);
      const outside = await listOsvInspections(stranger, {});
      expect(outside.total).toBe(0);
      await expect(readOsvInspection(stranger, {
        inspectionId,
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("leaves original inventory and findings unchanged", async () => {
      expect(await db.assetInventoryDevice.count({
        where: { organizationId: org, importId },
      })).toBe(2);
      expect(await db.assetInventoryImport.count({
        where: { organizationId: org, id: importId, state: "COMMITTED" },
      })).toBe(1);
    });
    it("does not permit an inspection after the associated snapshot retires", async () => {
      await retireAssetInventory(admin, {
        importId,
        expectedState: "COMMITTED",
        reason: "The synthetic inventory has been superseded.",
      }, now);
      query.mockClear();
      await expect(persistOsvInspection(admin, {
        ...args(), requestKey: "different-ledger-" + suffix,
      }, { query, now: () => now }))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(query).not.toHaveBeenCalled();
      expect(await db.assetOsvInspection.count({
        where: { organizationId: org },
      })).toBe(1);
    });
  },
);
