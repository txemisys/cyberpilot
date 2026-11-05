import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  importAssetInventory, listAssetInventoryDevices,
  listAssetInventoryImports, retireAssetInventory,
} from "./assets-inventory-service";
import type { AssetScope } from "./assets-inventory-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "phase 4 Assets durable CSV import, audit and tenant isolation", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "assets-org-" + nonce;
    const other = "assets-other-" + nonce;
    const admin = "assets-admin-" + nonce;
    const member = "assets-member-" + nonce;
    const outsider = "assets-outsider-" + nonce;
    const role: AssetScope = {
      organizationId: org, userId: admin, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: member, role: "MEMBER",
    };
    const foreign: AssetScope = {
      organizationId: other, userId: outsider, role: "ADMIN",
    };
    const now = new Date("2026-11-05T12:00:00.000Z");
    const csv = [
      "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
      "device-001,laptop-one,Alex Employee,WINDOWS,Windows 11,23H2,Example Browser,4.0.2,2026-11-04T12:00:00.000Z",
      "device-002,server-two,,LINUX,Ubuntu,22.04,Example Server,2.0,2026-10-01T12:00:00.000Z",
      "device-001,laptop-one,Alex Employee,WINDOWS,Windows 11,23H2,Example Browser,4.0.2,2026-11-04T12:00:00.000Z",
    ].join("\n") + "\n";
    const request = {
      sourceLabel: "Synthetic export",
      idempotencyKey: "assets-first-" + nonce,
      csv, dryRun: false,
    };
    let importId = "";
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: admin, name: "Asset admin",
            email: "asset-admin-" + nonce + "@example.invalid" },
          { id: member, name: "Asset member",
            email: "asset-member-" + nonce + "@example.invalid" },
          { id: outsider, name: "Asset foreign",
            email: "asset-foreign-" + nonce + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: org, name: "Asset organization", slug: "asset-" + nonce },
          { id: other, name: "Asset foreign organization",
            slug: "asset-other-" + nonce },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: org, userId: admin, role: "ADMIN" },
          { organizationId: org, userId: member, role: "MEMBER" },
          { organizationId: other, userId: outsider, role: "ADMIN" },
        ],
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, other] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [admin, member, outsider] } },
      });
    });
    it("denies non-admin writes but grants tenant-scoped read access", async () => {
      await expect(importAssetInventory(reader, request, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      const empty = await listAssetInventoryImports(reader, {});
      expect(empty.total).toBe(0);
    });
    it("previews without persisting any data", async () => {
      const result = await importAssetInventory(role,
        { ...request, dryRun: true }, now);
      expect(result.dryRun).toBe(true);
      expect(result.report.declaredCount).toBe(3);
      expect(result.report.importedCount).toBe(2);
      expect(result.report.duplicateCount).toBe(1);
      expect(await db.assetInventoryImport.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("commits normalized observations and audit atomically", async () => {
      const result = await importAssetInventory(role, request, now);
      expect(result.dryRun).toBe(false);
      expect(result.replayed).toBe(false);
      expect(result.importId).toEqual(expect.any(String));
      importId = result.importId!;
      const rows = await listAssetInventoryDevices(reader, { importId });
      expect(rows.total).toBe(2);
      expect(rows.devices.every(row => row.importId === importId)).toBe(true);
      expect(rows.devices.some(row => row.ownerHash === "Alex Employee"))
        .toBe(false);
      const audits = await db.auditEvent.findMany({
        where: {
          organizationId: org,
          resourceId: importId,
          action: "assets.csv.import.committed",
        },
      });
      expect(audits).toHaveLength(1);
    });
    it("replays with a stable key after observation freshness has changed", async () => {
      const later = new Date("2027-03-10T12:00:00.000Z");
      const result = await importAssetInventory(role, request, later);
      expect(result.replayed).toBe(true);
      expect(result.importId).toBe(importId);
      expect(await db.assetInventoryImport.count({
        where: { organizationId: org },
      })).toBe(1);
      expect(await db.assetInventoryDevice.count({
        where: { organizationId: org },
      })).toBe(2);
    });
    it("rejects idempotency-key reuse for a different source", async () => {
      await expect(importAssetInventory(role, {
        ...request, sourceLabel: "Different export",
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("isolates snapshots from other organizations", async () => {
      expect((await listAssetInventoryDevices(foreign, {})).total).toBe(0);
      expect((await listAssetInventoryImports(foreign, {})).total).toBe(0);
      await expect(listAssetInventoryDevices(foreign, { importId }))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("filters by declared platform and unknown advisory posture", async () => {
      const windows = await listAssetInventoryDevices(reader, {
        importId, platform: "WINDOWS", advisoryStatus: "UNKNOWN",
      });
      expect(windows.total).toBe(1);
      expect(windows.devices[0]?.externalId).toBe("device-001");
      const paginated = await listAssetInventoryDevices(reader, {
        importId, limit: 1, offset: 0,
      });
      expect(paginated.total).toBe(2);
      expect(paginated.hasMore).toBe(true);
    });
    it("requires explicit retirement and keeps audit trail", async () => {
      await expect(retireAssetInventory(reader, {
        importId, reason: "Superseded by later complete export.",
        expectedState: "COMMITTED",
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      const result = await retireAssetInventory(role, {
        importId, reason: "Superseded by later complete export.",
        expectedState: "COMMITTED",
      }, now);
      expect(result.state).toBe("RETIRED");
      expect((await listAssetInventoryImports(reader, {})).total).toBe(0);
      expect((await listAssetInventoryDevices(reader, {})).total).toBe(0);
      expect((await listAssetInventoryDevices(reader, {
        importId, includeRetired: true,
      })).total).toBe(2);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, resourceId: importId,
          action: "assets.csv.import.retired",
        },
      })).toBe(1);
      await expect(retireAssetInventory(role, {
        importId, reason: "Repeat retirement must reject.",
        expectedState: "COMMITTED",
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
  },
);
