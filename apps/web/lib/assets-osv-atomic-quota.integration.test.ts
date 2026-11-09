import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import {
  reserveOfficialOsvQuota, settleOfficialOsvQuota,
  inspectOfficialOsvQuota, createOsvQuotaCommand,
} from "./assets-osv-atomic-quota";
import { inspectOfficialOsv } from "./assets-osv-official-service";
import type { AssetScope } from "./assets-inventory-service";
import { importAssetInventory } from "./assets-inventory-service";
import type { LiveOsvQueryResult } from "./assets-osv-official-client";
const today = new Date("2026-11-09T12:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV atomic quota enforcement with PostgreSQL", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "quota-org-" + nonce;
    const foreign = "quota-other-" + nonce;
    const adminId = "quota-admin-" + nonce;
    const outsiderId = "quota-foreign-user-" + nonce;
    const readerId = "quota-reader-" + nonce;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: outsiderId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: readerId, role: "MEMBER",
    };
    const policy = {
      dailyInspectionLimit: 3,
      dailyRequestLimit: 8,
      maxReservedRequestsPerInspection: 6,
    };
    const bindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }];
    let importId = "";
    const command = (key: string, packages = 1, pages = 2) =>
      createOsvQuotaCommand(org, importId, packages, pages, key);
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Quota admin",
          email: "quota-admin-" + nonce + "@example.invalid" },
        { id: outsiderId, name: "Quota outsider",
          email: "quota-outsider-" + nonce + "@example.invalid" },
        { id: readerId, name: "Quota reader",
          email: "quota-reader-" + nonce + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Quota tests", slug: "quota-tests-" + nonce },
        { id: foreign, name: "Quota foreign",
          slug: "quota-foreign-" + nonce },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: readerId, role: "MEMBER" },
        { organizationId: foreign, userId: outsiderId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "device-001,host-1,,LINUX,Ubuntu,24.04,Example Package,1.0.0,2026-11-08T12:00:00.000Z",
        ].join("\n") + "\n",
        sourceLabel: "Quota integration fixture",
        idempotencyKey: "quota-import-" + nonce,
        dryRun: false,
      }, today);
      importId = imported.importId!;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, outsiderId, readerId] } },
      });
    });
    it("rejects a non-administrator before altering database quotas", async () => {
      await expect(reserveOfficialOsvQuota(reader,
        command("non-admin-denied-" + nonce), today, policy))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectOfficialOsvQuota(reader, today))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(await db.assetOsvQuotaDay.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("reserves a daily budget atomically with an append-only journal", async () => {
      const reserved = await reserveOfficialOsvQuota(admin,
        command("quota-first-" + nonce, 2, 2), today, policy);
      expect(reserved.state).toBe("RESERVED");
      expect(reserved.replayed).toBe(false);
      expect(reserved.inspectionsReserved).toBe(1);
      expect(reserved.requestsReserved).toBe(4);
      const rows = await db.assetOsvQuotaReservation.findMany({
        where: { organizationId: org },
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.reservedRequests).toBe(4);
    });
    it("returns duplicate same-key reservations without double-charging", async () => {
      const second = await reserveOfficialOsvQuota(admin,
        command("quota-first-" + nonce, 2, 2), today, policy);
      expect(second.replayed).toBe(true);
      expect(second.inspectionsReserved).toBe(1);
      expect(second.requestsReserved).toBe(4);
      await expect(reserveOfficialOsvQuota(admin,
        command("quota-first-" + nonce, 1, 2), today, policy))
        .rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("serializes concurrent reservations from two requests", async () => {
      const entries = await Promise.allSettled([
        reserveOfficialOsvQuota(admin,
          command("quota-concurrent-a-" + nonce, 1, 2), today, policy),
        reserveOfficialOsvQuota(admin,
          command("quota-concurrent-b-" + nonce, 1, 2), today, policy),
      ]);
      const accepted = entries.filter(row => row.status === "fulfilled");
      expect(accepted).toHaveLength(2);
      const day = await db.assetOsvQuotaDay.findUniqueOrThrow({
        where: { organizationId_utcDay: {
          organizationId: org,
          utcDay: new Date("2026-11-09T00:00:00.000Z"),
        } },
      });
      expect(day.inspectionsReserved).toBe(3);
      expect(day.requestsReserved).toBe(8);
    });
    it("refuses additional quotas without a fourth provider request", async () => {
      await expect(reserveOfficialOsvQuota(admin,
        command("quota-exhausted-" + nonce, 1, 1), today, policy))
        .rejects.toMatchObject({ code: "CONFLICT" });
      const snapshot = await inspectOfficialOsvQuota(admin, today);
      expect(snapshot.inspectionsRemaining).toBe(0);
      expect(snapshot.requestsRemaining).toBe(0);
      expect(snapshot.reservationsTotal).toBe(3);
      expect(snapshot.reservations).toHaveLength(3);
    });
    it("settles a reserved operation without refunding unused HTTP pages", async () => {
      const saved = await reserveOfficialOsvQuota(admin,
        command("quota-first-" + nonce, 2, 2), today, policy);
      const settled = await settleOfficialOsvQuota(admin,
        saved, "FINISHED", 1, today);
      expect(settled.state).toBe("FINISHED");
      const replay = await settleOfficialOsvQuota(admin,
        saved, "FINISHED", 1, today);
      expect(replay.replayed).toBe(true);
      await expect(settleOfficialOsvQuota(admin,
        saved, "FAILED", 1, today)).rejects
        .toMatchObject({ code: "CONFLICT" });
      const budget = await inspectOfficialOsvQuota(admin, today);
      expect(budget.requestsReserved).toBe(8);
    });
    it("uses a separate UTC-day bucket with full capacity", async () => {
      const later = new Date("2026-11-10T00:05:00.000Z");
      const next = await reserveOfficialOsvQuota(admin,
        command("quota-nextday-" + nonce, 1, 3),
        later, policy);
      expect(next.inspectionsReserved).toBe(1);
      expect(next.requestsReserved).toBe(3);
      const old = await inspectOfficialOsvQuota(admin, today);
      expect(old.inspectionsReserved).toBe(3);
    });
    it("keeps foreign tenant capacity independent", async () => {
      const foreignCommand = createOsvQuotaCommand(
        foreign, importId, 1, 2, "foreign-quota-" + nonce);
      const result = await reserveOfficialOsvQuota(
        outsider, foreignCommand, today, policy);
      expect(result.inspectionsReserved).toBe(1);
      const own = await inspectOfficialOsvQuota(admin, today);
      expect(own.inspectionsReserved).toBe(3);
    });
    it("blocks provider-side work when hard quota is exhausted", async () => {
      const query = vi.fn(async () => ({
        schema: "cyberpilot.assets.osv.live.query.v1" as const,
        endpoint: "https://api.osv.dev" as const,
        package: { ecosystem: "npm", name: "example-package",
          version: "1.0.0" },
        checkedAt: today.toISOString(),
        provider: "OSV_DEV_API" as const,
        transport: "HTTPS_FIXED_ENDPOINT" as const,
        status: "COMPLETE" as const,
        queriedPages: 1, responseBytes: 120,
        vulnerabilities: [],
        providerReportedCount: 0, exactEnumeratedCount: 0,
        nonEnumeratedCount: 0, withdrawnCount: 0,
        warnings: [], digest: "a".repeat(64),
      } satisfies LiveOsvQueryResult));
      await expect(inspectOfficialOsv(admin, {
        importId, packageBindings: bindings,
        limitPackages: 1, maxPagesPerPackage: 1,
        maxRecordsPerPackage: 10, maxAgeMinutes: 60, dryRun: false,
      }, { query, now: () => today })).rejects
        .toMatchObject({ code: "CONFLICT" });
      expect(query).not.toHaveBeenCalled();
    });
    it("does not charge provider quota for a dry-run preview", async () => {
      const before = await inspectOfficialOsvQuota(admin, today);
      const preview = await inspectOfficialOsv(admin, {
        importId, packageBindings: bindings,
        limitPackages: 1, maxPagesPerPackage: 1,
        maxRecordsPerPackage: 10, maxAgeMinutes: 60, dryRun: true,
      }, { now: () => today });
      expect(preview.status).toBe("PREVIEW");
      const after = await inspectOfficialOsvQuota(admin, today);
      expect(after.inspectionsReserved).toBe(before.inspectionsReserved);
      expect(after.requestsReserved).toBe(before.requestsReserved);
    });
  },
);
