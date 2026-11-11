import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import type { AssetScope } from "./assets-inventory-service";
import {
  createAssetReleaseReview, listAssetReleaseReviews,
  transitionAssetReleaseReview, REQUIRED_ACKNOWLEDGEMENTS,
} from "./assets-release-review-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "PostgreSQL conservative manual asset release reviews", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 15);
    const organizationId = "release-org-" + token;
    const foreignId = "release-foreign-" + token;
    const adminId = "release-admin-" + token;
    const readerId = "release-reader-" + token;
    const outsiderId = "release-outsider-" + token;
    const admin: AssetScope = {
      organizationId, userId: adminId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId, userId: readerId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreignId, userId: outsiderId, role: "ADMIN",
    };
    const now = new Date("2026-11-10T12:00:00.000Z");
    const reason =
      "Reviewed stored inventory and source limits before making a decision.";
    const bindings = [{
      inventoryProduct: "Example Package", ecosystem: "npm",
      packageName: "example-package", expectedPurl: null,
    }];
    let importId = "";
    let inspectionId = "";
    let reviewId = "";
    let bundleDigest = "";
    const command = () => ({
      importId, inspectionId, bindings,
      acceptancePolicy: {}, privacyPolicy: {},
      acknowledgements: [], exclusions: [
        "Live OSV dispatch not tested",
        "Backup erasure not verified",
      ], reason,
    });
    const transition = (operation: string, revision: number,
      acknowledgements: string[] = []) => ({
        reviewId, expectedRevision: revision,
        expectedEvidenceBundleDigest: bundleDigest,
        operation, reason, acknowledgements,
        bindings, acceptancePolicy: {}, privacyPolicy: {},
      });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Release admin",
          email: "release-admin-" + token + "@example.invalid" },
        { id: readerId, name: "Release reader",
          email: "release-reader-" + token + "@example.invalid" },
        { id: outsiderId, name: "Release outsider",
          email: "release-foreign-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: organizationId, slug: "release-org-" + token,
          name: "Offline release organization" },
        { id: foreignId, slug: "release-foreign-" + token,
          name: "Other offline organization" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId, userId: adminId, role: "ADMIN" },
        { organizationId, userId: readerId, role: "MEMBER" },
        { organizationId: foreignId, userId: outsiderId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        sourceLabel: "Synthetic local acceptance inventory",
        idempotencyKey: "release-import-" + token,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "host-001,host-001,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-09T10:00:00.000Z",
        ].join("\n") + "\n",
      }, now);
      importId = imported.importId!;
      const inspection = await db.assetOsvInspection.create({ data: {
        organizationId, inventoryImportId: importId,
        requestKey: "release-provider-key-" + token,
        requestDigest: "a".repeat(64),
        reportDigest: "b".repeat(64),
        status: "COMPLETE", provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 1, completedCount: 1,
        possibleCount: 0, providerOnlyCount: 0,
        completedAt: now,
        report: { schema: "fixture.synthetic.release.v1" },
        queries: { create: [{
          organizationId, queryKey: "c".repeat(64),
          ecosystem: "npm", packageName: "example-package",
          version: "1.2.3", providerStatus: "COMPLETE",
          providerDigest: "d".repeat(64), checkedAt: now,
          observationCount: 0, pageCount: 1,
          possibleIds: [], providerOnlyIds: [],
          withdrawnIds: [], unresolvedIds: [],
        }] },
      } });
      inspectionId = inspection.id;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, foreignId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, readerId, outsiderId] } },
      });
    });
    it("denies members and foreign administrators before creating evidence", async () => {
      await expect(createAssetReleaseReview(reader, command(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(createAssetReleaseReview(outsider, command(), now))
        .rejects.toMatchObject({ code: "MISSING" });
      expect(await db.assetReleaseReview.count({
        where: { organizationId },
      })).toBe(0);
    });
    it("records a pending human review and its audit atomically", async () => {
      const result = await createAssetReleaseReview(admin, command(), now);
      expect(result.replayed).toBe(false);
      expect(result.review).toMatchObject({
        organizationId, state: "PENDING", revision: 1,
        operatorUserId: adminId,
      });
      expect(result.review.verification.reasons).toEqual([]);
      reviewId = result.review.id;
      bundleDigest = result.review.evidenceBundleDigest;
      expect(result.review.scenarioSummary).toMatchObject({
        synthetic: true, totalExecuted: 13,
      });
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId,
          action: "assets.release.review.created" },
      })).toBe(1);
      expect(await db.assetReleaseReview.count({
        where: { organizationId },
      })).toBe(1);
    });
    it("returns matching existing evidence without duplicate audit", async () => {
      const result = await createAssetReleaseReview(admin, command(), now);
      expect(result.replayed).toBe(true);
      expect(result.review.id).toBe(reviewId);
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId,
          action: "assets.release.review.created" },
      })).toBe(1);
    });
    it("lists only reviews of the authenticated organization", async () => {
      const ours = await listAssetReleaseReviews(admin);
      const foreign = await listAssetReleaseReviews(outsider);
      expect(ours.total).toBe(1);
      expect(ours.reviews[0]!.id).toBe(reviewId);
      expect(foreign.total).toBe(0);
      await expect(listAssetReleaseReviews(reader))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("rejects wrong CAS revision and source fingerprint without writes", async () => {
      await expect(transitionAssetReleaseReview(admin, {
        ...transition("START_REVIEW", 5),
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(transitionAssetReleaseReview(admin, {
        ...transition("START_REVIEW", 1),
        expectedEvidenceBundleDigest: "f".repeat(64),
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId },
      })).toBe(1);
    });
    it("begins a human review with one CAS revision and one audit", async () => {
      const result = await transitionAssetReleaseReview(admin,
        transition("START_REVIEW", 1), now);
      expect(result.review.state).toBe("IN_REVIEW");
      expect(result.review.revision).toBe(2);
      bundleDigest = result.review.evidenceBundleDigest;
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId,
          action: "assets.release.review.start_review" },
      })).toBe(1);
    });
    it("cannot implicitly accept a release without explicit human acknowledgement", async () => {
      await expect(transitionAssetReleaseReview(admin,
        transition("ACCEPT_OFFLINE", 2), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.assetReleaseReview.findUniqueOrThrow({
        where: { id: reviewId },
      })).toMatchObject({ state: "IN_REVIEW", revision: 2 });
    });
    it("does not turn synthetic success into privacy/retention approval", async () => {
      await expect(transitionAssetReleaseReview(admin,
        transition("ACCEPT_OFFLINE", 2,
          [...REQUIRED_ACKNOWLEDGEMENTS]), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId,
          action: "assets.release.review.accept_offline" },
      })).toBe(0);
    });
    it("records explicit rejection and guards repeated decisions", async () => {
      const decision = await transitionAssetReleaseReview(admin,
        transition("REJECT", 2), now);
      expect(decision.review).toMatchObject({
        state: "REJECTED", revision: 3,
        decidedByUserId: adminId,
      });
      bundleDigest = decision.review.evidenceBundleDigest;
      await expect(transitionAssetReleaseReview(admin,
        transition("REJECT", 2), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId,
          action: "assets.release.review.reject" },
      })).toBe(1);
    });
    it("can explicitly reopen a rejected decision without pretending LIVE success", async () => {
      const result = await transitionAssetReleaseReview(admin,
        transition("REOPEN", 3), now);
      expect(result.review).toMatchObject({
        state: "REOPENED", revision: 4,
        decidedAt: null, decidedByUserId: null,
      });
      expect(await db.auditEvent.count({
        where: { organizationId, resourceId: reviewId,
          action: "assets.release.review.reopen" },
      })).toBe(1);
      expect(await db.securityFinding.count({
        where: { organizationId },
      })).toBe(0);
    });
    it("never exposes a foreign review through a forged ID", async () => {
      await expect(transitionAssetReleaseReview(outsider,
        transition("START_REVIEW", 4), now))
        .rejects.toMatchObject({ code: "MISSING" });
      await expect(transitionAssetReleaseReview(reader,
        transition("START_REVIEW", 4), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
  });
