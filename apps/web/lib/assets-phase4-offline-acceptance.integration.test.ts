import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import { inspectAssetActionGuidance } from "./assets-action-guidance-service";
import { openAssetAdviceCase } from "./assets-action-case-service";
import { inspectAssetOfflineAcceptance } from "./assets-offline-acceptance-service";
import { inspectAssetPrivacyReadiness } from "./assets-privacy-readiness-service";
import type { AssetScope } from "./assets-inventory-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "Fase 4 offline acceptance and privacy PostgreSQL read-only journey", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 15);
    const organizationId = "accept-release-org-" + token;
    const foreignId = "accept-release-foreign-" + token;
    const adminId = "accept-release-admin-" + token;
    const readerId = "accept-release-reader-" + token;
    const outsiderId = "accept-release-outside-" + token;
    const scope: AssetScope = {
      organizationId, userId: adminId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId, userId: readerId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreignId, userId: outsiderId, role: "ADMIN",
    };
    const when = new Date("2026-11-10T12:00:00.000Z");
    const bindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
      expectedPurl: null,
    }];
    let importId = "";
    let inspectionId = "";
    let fingerprint = "";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Fase 4 admin",
          email: "fase4-admin-" + token + "@example.invalid" },
        { id: readerId, name: "Fase 4 reader",
          email: "fase4-reader-" + token + "@example.invalid" },
        { id: outsiderId, name: "Fase 4 outsider",
          email: "fase4-outsider-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: organizationId, name: "Fase 4 acceptance",
          slug: "fase4-accept-" + token },
        { id: foreignId, name: "Fase 4 outside",
          slug: "fase4-outside-" + token },
      ] });
      await db.membership.createMany({ data: [
        { organizationId, userId: adminId, role: "ADMIN" },
        { organizationId, userId: readerId, role: "MEMBER" },
        { organizationId: foreignId, userId: outsiderId, role: "ADMIN" },
      ] });
      const importResult = await importAssetInventory(scope, {
        sourceLabel: "Synthetic Fase 4 release acceptance",
        idempotencyKey: "fase4-accept-" + token,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "host-001,personal-host-001,owner-001,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-08T10:00:00.000Z",
        ].join("\n") + "\n",
      }, when);
      importId = importResult.importId!;
      const inspection = await db.assetOsvInspection.create({ data: {
        organizationId, inventoryImportId: importId,
        requestKey: "fase4-accept-osv-" + token,
        requestDigest: "a".repeat(64),
        reportDigest: "b".repeat(64),
        status: "COMPLETE", provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 1, completedCount: 1,
        possibleCount: 1, providerOnlyCount: 0,
        completedAt: when,
        report: { schema: "synthetic.fase4.offline.v1" },
        queries: { create: [{
          organizationId, queryKey: "c".repeat(64),
          ecosystem: "npm", packageName: "example-package",
          version: "1.2.3", providerStatus: "COMPLETE",
          providerDigest: "d".repeat(64), checkedAt: when,
          observationCount: 1, pageCount: 1,
          possibleIds: ["GHSA-aaaa-bbbb-cccc"],
          providerOnlyIds: [], withdrawnIds: [], unresolvedIds: [],
        }] },
      } });
      inspectionId = inspection.id;
      const guidance = await inspectAssetActionGuidance(scope,
        { importId, inspectionId, bindings }, when);
      fingerprint = guidance.rows[0]!.evidenceFingerprint;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, foreignId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, readerId, outsiderId] } },
      });
    });
    it("blocks a release assessment without review of its candidate evidence", async () => {
      const result = await inspectAssetOfflineAcceptance(scope, {
        importId, inspectionId, bindings,
        policy: { minimumMappedPercent: 100 },
      }, when);
      expect(result.scorecard.possibleCandidatesWithoutReview).toBe(1);
      expect(result.acceptanceEligible).toBe(false);
      expect(result.providerRequests).toBe(0);
      expect(result.databaseWrites).toBe(0);
    });
    it("rejects member and foreign tenant access before acceptance data is loaded", async () => {
      await expect(inspectAssetOfflineAcceptance(reader, {
        importId, inspectionId, bindings,
      }, when)).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectAssetOfflineAcceptance(outsider, {
        importId, inspectionId, bindings,
      }, when)).rejects.toMatchObject({ code: "MISSING" });
      await expect(inspectAssetPrivacyReadiness(reader, {}, when))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("allows local assessment when evidence-backed human case exists", async () => {
      await openAssetAdviceCase(scope, {
        importId, inspectionId, bindings,
        evidenceFingerprint: fingerprint,
        reason: "Human evidence review required before releasing the asset workflow.",
      }, when);
      const result = await inspectAssetOfflineAcceptance(scope, {
        importId, inspectionId, bindings,
        policy: { minimumMappedPercent: 100 },
      }, when);
      expect(result.scorecard.blocked).toBe(0);
      expect(result.manualAcceptanceStillRequired).toBe(true);
      expect(result.source.auditCount).toBe(1);
      expect(result.source.reviewCaseCount).toBe(1);
      expect(result.cyberScoreModified).toBe(false);
    });
    it("reports hostnames and pseudonymous owner hashes without exposing originals", async () => {
      const result = await inspectAssetPrivacyReadiness(scope, {}, when);
      expect(result.totalPotentialHostnames).toBe(1);
      expect(result.totalOwnerHashes).toBe(1);
      expect(result.totalLinkedCases).toBe(1);
      expect(result.imports[0]?.possiblePersonalData).toBe(true);
      expect(JSON.stringify(result)).not.toContain("owner-001");
      expect(JSON.stringify(result)).not.toContain("personal-host-001");
    });
    it("does not expose the organization's records to a foreign administrator", async () => {
      const result = await inspectAssetPrivacyReadiness(outsider, {}, when);
      expect(result.imports).toEqual([]);
      expect(result.importedCount).toBe(0);
      expect(result.totalLinkedCases).toBe(0);
    });
    it("does not change any persisted source evidence while assessing", async () => {
      const before = await Promise.all([
        db.assetInventoryDevice.count({ where: { organizationId } }),
        db.assetOsvInspection.count({ where: { organizationId } }),
        db.assetAdviceCase.count({ where: { organizationId } }),
        db.auditEvent.count({ where: { organizationId } }),
      ]);
      await inspectAssetOfflineAcceptance(scope, {
        importId, inspectionId, bindings,
      }, when);
      await inspectAssetPrivacyReadiness(scope, {}, when);
      const after = await Promise.all([
        db.assetInventoryDevice.count({ where: { organizationId } }),
        db.assetOsvInspection.count({ where: { organizationId } }),
        db.assetAdviceCase.count({ where: { organizationId } }),
        db.auditEvent.count({ where: { organizationId } }),
      ]);
      expect(after).toEqual(before);
    });
    it("rejects policy previews that claim unsupported immediate erasure", async () => {
      await expect(inspectAssetPrivacyReadiness(scope, {
        deleteBackupsImmediately: true,
      }, when)).rejects.toMatchObject({ code: "INVALID" });
    });
  },
);
