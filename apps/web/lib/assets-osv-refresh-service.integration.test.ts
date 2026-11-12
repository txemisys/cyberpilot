import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import {
  inspectOsvRefreshReadiness, inspectOsvHistoryDelta,
  parseRefreshRequest, parseDeltaRequest, queryToRefreshRow,
} from "./assets-osv-refresh-service";
import type { AssetScope } from "./assets-inventory-service";

describe("OSV refresh service input contracts", () => {
  it("rejects missing tenant inventory and illegal policy fields", () => {
    expect(() => parseRefreshRequest({ policy: {} })).toThrow();
    expect(() => parseRefreshRequest({
      importId: "import-12345", policy: { irrelevant: true },
    })).toThrow();
    expect(() => parseRefreshRequest({
      importId: "import-12345", offset: -1,
    })).toThrow();
    expect(parseRefreshRequest({ importId: "import-12345" }))
      .toMatchObject({
        importId: "import-12345", offset: 0, limit: 50,
      });
  });
  it("requires two different valid inspection identifiers", () => {
    expect(() => parseDeltaRequest({
      previousInspectionId: "inspection-12345",
      currentInspectionId: "inspection-12345",
    })).toThrow();
    expect(() => parseDeltaRequest({
      previousInspectionId: "inspection-12345",
    })).toThrow();
  });
  it("removes invalid advisory strings from a persisted legacy JSON list", () => {
    const parsed = queryToRefreshRow({
      queryKey: "a".repeat(64), inspectionId: "inspection-12345",
      ecosystem: "npm", packageName: "sample", version: "1.2.3",
      providerStatus: "COMPLETE", checkedAt: new Date(),
      observationCount: 1,
      possibleIds: [
        "GHSA-abcd-1234-5678", "GHSA-abcd-1234-5678", "a\u0000b",
      ],
      providerOnlyIds: {}, unresolvedIds: null,
      withdrawnIds: [],
    });
    expect(parsed.possibleIds).toEqual(["GHSA-abcd-1234-5678"]);
    expect(parsed.providerOnlyIds).toEqual([]);
  });
});
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV refresh and comparison real PostgreSQL tenant boundaries", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "osv-delta-" + suffix;
    const other = "osv-delta-other-" + suffix;
    const userId = "osv-delta-reader-" + suffix;
    const outsiderId = "osv-delta-outsider-" + suffix;
    const scope: AssetScope = {
      organizationId: org, userId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: other, userId: outsiderId, role: "ADMIN",
    };
    const now = new Date("2026-11-05T12:00:00.000Z");
    const prior = new Date("2026-11-01T12:00:00.000Z");
    const later = new Date("2026-11-05T08:00:00.000Z");
    const sourceCsv = [
      "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
      "device-001,host-a,,LINUX,Ubuntu,22.04,Example Package,1.2.3,2026-10-01T12:00:00.000Z",
    ].join("\n") + "\n";
    let importId = "";
    let earlierId = "";
    let currentId = "";
    async function saveInspection(
      id: string, at: Date, ids: string[], status: string,
    ) {
      await db.assetOsvInspection.create({
        data: {
          id, organizationId: org, inventoryImportId: importId,
          requestKey: "refresh-test-" + id,
          requestDigest: "a".repeat(64),
          reportDigest: "b".repeat(64),
          status, provider: "OSV_DEV_API",
          coverage: "DECLARED_NOT_VERIFIED",
          queryCount: 1, completedCount: status === "COMPLETE" ? 1 : 0,
          possibleCount: ids.length, providerOnlyCount: 0,
          completedAt: at,
          report: {
            schema: "cyberpilot.assets.osv.official.inspection.v1",
            organizationId: org, importId, status,
            reportDigest: "b".repeat(64),
            coverage: "DECLARED_NOT_VERIFIED", dryRun: false,
            results: [],
          },
          queries: {
            create: [{
              organizationId: org, queryKey: "c".repeat(64),
              ecosystem: "npm", packageName: "example-package",
              version: "1.2.3", providerStatus: status,
              providerDigest: "d".repeat(64), checkedAt: at,
              possibleIds: ids, providerOnlyIds: [],
              unresolvedIds: [], withdrawnIds: [],
              observationCount: 1, pageCount: 1,
            }],
          },
        },
      });
    }
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: userId, name: "OSV delta reader",
          email: "osv-delta-reader-" + suffix + "@example.invalid" },
        { id: outsiderId, name: "OSV delta outsider",
          email: "osv-delta-outside-" + suffix + "@example.invalid" },
      ]});
      await db.organization.createMany({ data: [
        { id: org, name: "OSV delta fixture",
          slug: "osv-delta-" + suffix },
        { id: other, name: "Foreign OSV delta fixture",
          slug: "osv-delta-other-" + suffix },
      ]});
      await db.membership.createMany({ data: [
        { organizationId: org, userId, role: "MEMBER" },
        { organizationId: other, userId: outsiderId, role: "ADMIN" },
      ]});
      const imported = await importAssetInventory({
        organizationId: org, userId, role: "ADMIN",
      }, {
        sourceLabel: "OSV delta fixture",
        idempotencyKey: "osv-delta-import-" + suffix,
        csv: sourceCsv, dryRun: false,
      }, now);
      importId = imported.importId!;
      earlierId = "osv-delta-prior-" + suffix;
      currentId = "osv-delta-current-" + suffix;
      await saveInspection(earlierId, prior, [
        "GHSA-aaaa-1111-2222",
      ], "COMPLETE");
      await saveInspection(currentId, later, [
        "GHSA-bbbb-3333-4444",
      ], "COMPLETE");
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, other] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, outsiderId] } },
      });
    });
    it("calculates refresh freshness from the newest scoped saved query", async () => {
      const result = await inspectOsvRefreshReadiness(scope, {
        importId, policy: {
          freshnessMinutes: 60, maximumPackagesPerRun: 10,
        },
      }, now);
      expect(result.totalHistoricalPackages).toBe(1);
      expect(result.dueCount).toBe(1);
      expect(result.selectedCount).toBe(1);
      expect(result.selected[0]?.state).toBe("STALE");
      expect(result.selected[0]?.possibleIds)
        .toEqual(["GHSA-bbbb-3333-4444"]);
    });
    it("enforces organization permissions before returning history", async () => {
      await expect(inspectOsvRefreshReadiness(outsider, {
        importId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("never counts a foreign organization's results in refresh budgets", async () => {
      const result = await inspectOsvRefreshReadiness(scope, {
        importId,
      }, now);
      expect(result.budget.queryCountToday).toBe(1);
      expect(result.budget.inspectionCountToday).toBe(1);
    });
    it("compares two persisted OSV histories without inferring remediation", async () => {
      const result = await inspectOsvHistoryDelta(scope, {
        previousInspectionId: earlierId,
        currentInspectionId: currentId,
      });
      expect(result.completeComparison).toBe(true);
      expect(result.summary.comparedPackages).toBe(1);
      expect(result.summary.possibleAdded).toBe(1);
      expect(result.summary.possibleNoLongerListed).toBe(1);
      expect(result.rows.find(row =>
        row.kind === "POSSIBLE_ID_NOT_LISTED")?.explanation)
        .toMatch(/not proof of remediation/i);
    });
    it("hides cross-tenant inspection IDs", async () => {
      await expect(inspectOsvHistoryDelta(outsider, {
        previousInspectionId: earlierId,
        currentInspectionId: currentId,
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("rejects nonexistent comparisons without leaking tenant data", async () => {
      await expect(inspectOsvHistoryDelta(scope, {
        previousInspectionId: earlierId,
        currentInspectionId: "unavailable-inspection-12345",
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("performs no remote queries or database writes", async () => {
      const before = await db.assetOsvInspection.count({
        where: { organizationId: org },
      });
      await inspectOsvRefreshReadiness(scope, { importId }, now);
      await inspectOsvHistoryDelta(scope, {
        previousInspectionId: earlierId,
        currentInspectionId: currentId,
      });
      expect(await db.assetOsvInspection.count({
        where: { organizationId: org },
      })).toBe(before);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, action: "assets.osv.refresh.executed",
        },
      })).toBe(0);
    });
  },
);
