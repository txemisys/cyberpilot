import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import { executeOsvRenewal, previewOsvRenewal } from "./assets-osv-renewal";
import type { AssetScope } from "./assets-inventory-service";
import type { LiveOsvQueryResult } from "./assets-osv-official-client";
const now = new Date("2026-11-09T12:00:00.000Z");
const previousAt = new Date("2026-11-01T12:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV manual renewal integrates historical inventory and PostgreSQL quota", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "osv-renew-" + suffix;
    const foreign = "osv-renew-foreign-" + suffix;
    const adminId = "osv-renew-admin-" + suffix;
    const readerId = "osv-renew-reader-" + suffix;
    const outsiderId = "osv-renew-outsider-" + suffix;
    const scope: AssetScope = { organizationId: org, userId: adminId, role: "ADMIN" };
    const reader: AssetScope = {
      organizationId: org, userId: readerId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: outsiderId, role: "ADMIN",
    };
    const sourceCsv = [
      "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
      "device-01,host-01,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
      "device-02,host-02,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
    ].join("\n") + "\n";
    const bindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
    }];
    const query = vi.fn(async () => ({
      schema: "cyberpilot.assets.osv.live.query.v1" as const,
      endpoint: "https://api.osv.dev" as const,
      package: {
        ecosystem: "npm", name: "example-package", version: "1.2.3",
      },
      checkedAt: now.toISOString(), provider: "OSV_DEV_API" as const,
      transport: "HTTPS_FIXED_ENDPOINT" as const,
      status: "COMPLETE" as const, queriedPages: 1,
      responseBytes: 200,
      vulnerabilities: [{
        id: "GHSA-bbbb-3333-4444", modified: now.toISOString(),
        withdrawn: null, aliases: [],
        packageIdentityListed: true, exactVersionListed: true,
        rangesPresent: false, fingerprint: "b".repeat(64),
      }],
      providerReportedCount: 1, exactEnumeratedCount: 1,
      nonEnumeratedCount: 0, withdrawnCount: 0,
      warnings: [], digest: "e".repeat(64),
    } satisfies LiveOsvQueryResult));
    let importId = "";
    let sourceId = "";
    const key = "manual-osv-" + suffix;
    const input = (preview: boolean, digest: string | null = null) => ({
      sourceInspectionId: sourceId,
      requestKey: key,
      inspection: {
        importId, packageBindings: bindings, limitPackages: 5,
        maxPagesPerPackage: 2, maxRecordsPerPackage: 50,
        maxAgeMinutes: 60, dryRun: preview,
      },
      policy: {
        freshnessMinutes: 1440, minimumRetryMinutes: 60,
      },
      dryRun: preview, confirmOutbound: !preview,
      expectedPlanDigest: digest,
    });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "OSV renewal admin",
          email: "osv-renew-admin-" + suffix + "@example.invalid" },
        { id: readerId, name: "OSV renewal reader",
          email: "osv-renew-reader-" + suffix + "@example.invalid" },
        { id: outsiderId, name: "OSV renewal outsider",
          email: "osv-renew-outsider-" + suffix + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "OSV renewal fixture", slug: "osv-renew-" + suffix },
        { id: foreign, name: "Foreign OSV renewal fixture",
          slug: "osv-renew-foreign-" + suffix },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: readerId, role: "MEMBER" },
        { organizationId: foreign, userId: outsiderId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(scope, {
        csv: sourceCsv, sourceLabel: "OSV manual renewal fixture",
        idempotencyKey: "osv-renew-import-" + suffix, dryRun: false,
      }, now);
      importId = imported.importId!;
      const prior = await db.assetOsvInspection.create({
        data: {
          organizationId: org, inventoryImportId: importId,
          requestKey: "previous-osv-" + suffix,
          requestDigest: "a".repeat(64),
          reportDigest: "c".repeat(64),
          status: "COMPLETE", provider: "OSV_DEV_API",
          coverage: "DECLARED_NOT_VERIFIED",
          queryCount: 1, completedCount: 1, possibleCount: 1,
          providerOnlyCount: 0, completedAt: previousAt,
          report: {
            schema: "cyberpilot.assets.osv.official.inspection.v1",
            organizationId: org, importId, status: "COMPLETE",
            dryRun: false, coverage: "DECLARED_NOT_VERIFIED",
            reportDigest: "c".repeat(64), results: [],
          },
          queries: {
            create: [{
              organizationId: org,
              queryKey: "d".repeat(64),
              ecosystem: "npm", packageName: "example-package",
              version: "1.2.3", providerStatus: "COMPLETE",
              checkedAt: previousAt, providerDigest: "a".repeat(64),
              observationCount: 2, pageCount: 1,
              possibleIds: ["GHSA-aaaa-1111-2222"],
              providerOnlyIds: [], withdrawnIds: [], unresolvedIds: [],
            }],
          },
        },
      });
      sourceId = prior.id;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, readerId, outsiderId] } },
      });
    });
    it("blocks non-admin planning and all foreign tenant access", async () => {
      await expect(previewOsvRenewal(reader, input(true), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(previewOsvRenewal(outsider, input(true), now))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("previews without external provider access, quota charges or writes", async () => {
      query.mockClear();
      const before = await db.assetOsvInspection.count({
        where: { organizationId: org },
      });
      const plan = await previewOsvRenewal(scope, input(true), now);
      expect(plan.validForExecution).toBe(true);
      expect(plan.selectedPackages).toBe(1);
      expect(plan.maximumHttpPages).toBe(2);
      expect(plan.planDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(query).not.toHaveBeenCalled();
      expect(await db.assetOsvInspection.count({
        where: { organizationId: org },
      })).toBe(before);
      expect(await db.assetOsvQuotaReservation.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("rejects a tampered or stale approval before contacting the provider", async () => {
      query.mockClear();
      await expect(executeOsvRenewal(scope, input(false, "f".repeat(64)), {
        now: () => now, official: { query, now: () => now },
      })).rejects.toMatchObject({ code: "CONFLICT" });
      expect(query).not.toHaveBeenCalled();
      expect(await db.assetOsvQuotaReservation.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("executes one authorized renewal, persists the result and compares IDs", async () => {
      query.mockClear();
      const plan = await previewOsvRenewal(scope, input(true), now);
      const result = await executeOsvRenewal(scope,
        input(false, plan.planDigest), {
          now: () => now,
          official: { query, now: () => now },
        });
      expect(query).toHaveBeenCalledTimes(1);
      expect(result.status).toBe("COMPLETE");
      expect(result.replayed).toBe(false);
      expect(result.comparison?.summary.possibleAdded).toBe(1);
      expect(result.comparison?.summary.possibleNoLongerListed).toBe(1);
      expect(result.comparison?.completeComparison).toBe(true);
      const stored = await db.assetOsvInspection.findUniqueOrThrow({
        where: { id: result.currentInspectionId },
        include: { queries: true },
      });
      expect(stored.queries).toHaveLength(1);
      expect(stored.queries[0]?.possibleIds)
        .toEqual(["GHSA-bbbb-3333-4444"]);
      const quotas = await db.assetOsvQuotaDay.findMany({
        where: { organizationId: org },
      });
      expect(quotas).toHaveLength(1);
      expect(quotas[0]?.requestsReserved).toBe(2);
      expect(quotas[0]?.inspectionsReserved).toBe(1);
    });
    it("prevents repeated provider traffic when an authorized key was used", async () => {
      query.mockClear();
      const plan = await previewOsvRenewal(scope, input(true), now);
      await expect(executeOsvRenewal(scope, input(false, plan.planDigest), {
        now: () => now, official: { query, now: () => now },
      })).rejects.toMatchObject({ code: "CONFLICT" });
      expect(query).not.toHaveBeenCalled();
      expect(await db.assetOsvQuotaReservation.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("retains original inventory observations and historical source", async () => {
      expect(await db.assetInventoryDevice.count({
        where: { organizationId: org, importId },
      })).toBe(2);
      expect(await db.assetOsvInspection.findUnique({
        where: { id: sourceId },
      })).toMatchObject({ status: "COMPLETE" });
    });
  },
);
