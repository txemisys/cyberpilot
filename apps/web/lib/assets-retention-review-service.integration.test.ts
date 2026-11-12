import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import type { AssetScope } from "./assets-inventory-service";
import {
  createAssetRetentionReview, listAssetRetentionReviews,
  transitionAssetRetentionReview, inspectRetentionReviewReadiness,
} from "./assets-retention-review-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "PostgreSQL human retention exceptions and tenant-scoped audits", () => {
    const key = randomUUID().replaceAll("-", "").slice(0, 15);
    const orgId = "retention-org-" + key;
    const foreignId = "retention-foreign-" + key;
    const adminId = "retention-admin-" + key;
    const memberId = "retention-member-" + key;
    const foreignUser = "retention-outsider-" + key;
    const admin: AssetScope = { organizationId: orgId,
      userId: adminId, role: "ADMIN" };
    const member: AssetScope = { organizationId: orgId,
      userId: memberId, role: "MEMBER" };
    const outsider: AssetScope = { organizationId: foreignId,
      userId: foreignUser, role: "ADMIN" };
    const now = new Date("2026-11-11T10:00:00.000Z");
    const reason =
      "Investigated data processing and retention limits for this import.";
    let importId = "";
    let reviewId = "";
    let digest = "";
    const command = () => ({
      importId, policy: {}, reason,
      acknowledgements: [],
      exceptions: [],
      backupDisposition: "UNVERIFIED",
      personalDataDisposition: "REQUIRES_REVIEW",
      nextReviewAt: null,
    });
    const transition = (operation: string, expectedRevision: number) => ({
      reviewId, operation, expectedRevision,
      expectedPrivacyDigest: digest,
      policy: {}, reason,
      acknowledgements: [],
      exceptions: [], backupDisposition: "UNVERIFIED",
      personalDataDisposition: "REQUIRES_REVIEW",
      nextReviewAt: null,
    });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Retention reviewer",
          email: "retention-admin-" + key + "@example.invalid" },
        { id: memberId, name: "Retention reader",
          email: "retention-member-" + key + "@example.invalid" },
        { id: foreignUser, name: "Retention outsider",
          email: "retention-foreign-" + key + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: orgId, slug: "retention-org-" + key,
          name: "Retention example tenant" },
        { id: foreignId, slug: "retention-foreign-" + key,
          name: "Other retention example tenant" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: orgId, userId: adminId, role: "ADMIN" },
        { organizationId: orgId, userId: memberId, role: "MEMBER" },
        { organizationId: foreignId, userId: foreignUser, role: "ADMIN" },
      ] });
      const result = await importAssetInventory(admin, {
        sourceLabel: "Synthetic retention customer declaration",
        idempotencyKey: "retention-import-" + key,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "host-001,host-001,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-10T10:00:00.000Z",
        ].join("\n") + "\n",
      }, now);
      importId = result.importId!;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [orgId, foreignId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, foreignUser] } },
      });
    });
    it("refuses unauthorized or foreign preview access", async () => {
      await expect(inspectRetentionReviewReadiness(member,
        command(), now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectRetentionReviewReadiness(outsider,
        command(), now)).rejects.toMatchObject({ code: "MISSING" });
      expect(await db.assetRetentionReview.count({
        where: { organizationId: orgId },
      })).toBe(0);
    });
    it("previews actual persisted tenant data without writing an approval", async () => {
      const before = await db.assetRetentionReview.count({
        where: { organizationId: orgId },
      });
      const value = await inspectRetentionReviewReadiness(
        admin, command(), now);
      expect(value).toMatchObject({
        organizationId: orgId, importId,
        databaseWrites: 0, externalProviderRequests: 0,
        legalSignoffGranted: false, backupsErased: false,
      });
      expect(value.gates.length).toBeGreaterThan(0);
      expect(await db.assetRetentionReview.count({
        where: { organizationId: orgId },
      })).toBe(before);
    });
    it("creates one PENDING record and one audited event", async () => {
      await expect(createAssetRetentionReview(member,
        command(), now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(createAssetRetentionReview(outsider,
        command(), now)).rejects.toMatchObject({ code: "MISSING" });
      const created = await createAssetRetentionReview(
        admin, command(), now);
      expect(created.replayed).toBe(false);
      expect(created.review).toMatchObject({
        organizationId: orgId, state: "PENDING",
        revision: 1, requestedByUserId: adminId,
      });
      expect(created.review.verification.valid).toBe(true);
      reviewId = created.review.id;
      digest = created.review.privacyDigest;
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
        action: "assetRetention.review.created",
      } })).toBe(1);
    });
    it("replays matching requests with no duplicate audit", async () => {
      const again = await createAssetRetentionReview(
        admin, command(), now);
      expect(again.replayed).toBe(true);
      expect(again.review.id).toBe(reviewId);
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
        action: "assetRetention.review.created",
      } })).toBe(1);
    });
    it("returns only the scoped retention register", async () => {
      const ours = await listAssetRetentionReviews(admin);
      const theirs = await listAssetRetentionReviews(outsider);
      expect(ours.total).toBe(1);
      expect(ours.reviews[0]!.id).toBe(reviewId);
      expect(theirs.total).toBe(0);
      await expect(listAssetRetentionReviews(member))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("rejects stale CAS revisions and altered digests", async () => {
      await expect(transitionAssetRetentionReview(admin,
        transition("START_REVIEW", 9), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      await expect(transitionAssetRetentionReview(admin, {
        ...transition("START_REVIEW", 1),
        expectedPrivacyDigest: "f".repeat(64),
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
      } })).toBe(1);
    });
    it("records START_REVIEW with transaction audit and increments revision", async () => {
      const updated = await transitionAssetRetentionReview(
        admin, transition("START_REVIEW", 1), now);
      expect(updated.review).toMatchObject({
        state: "IN_REVIEW", revision: 2,
      });
      expect(updated.review.verification.valid).toBe(true);
      digest = updated.review.privacyDigest;
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
        action: "assetRetention.review.start_review",
      } })).toBe(1);
    });
    it("does not mark privacy approval without exceptions and owners", async () => {
      await expect(transitionAssetRetentionReview(admin,
        transition("DOCUMENT_EXCEPTIONS", 2), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      const row = await db.assetRetentionReview.findUniqueOrThrow({
        where: { id: reviewId },
      });
      expect(row.state).toBe("IN_REVIEW");
      expect(row.revision).toBe(2);
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
        action: "assetRetention.review.document_exceptions",
      } })).toBe(0);
    });
    it("rejects with an explicit reason and CAS audit", async () => {
      const result = await transitionAssetRetentionReview(
        admin, transition("REJECT", 2), now);
      expect(result.review).toMatchObject({
        state: "REJECTED", revision: 3,
        reviewedByUserId: adminId,
      });
      digest = result.review.privacyDigest;
      expect(result.legalApprovalVerified).toBe(false);
      expect(result.backupsErased).toBe(false);
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
        action: "assetRetention.review.reject",
      } })).toBe(1);
    });
    it("allows human re-opening without granting a disposal approval", async () => {
      const result = await transitionAssetRetentionReview(
        admin, transition("REOPEN", 3), now);
      expect(result.review).toMatchObject({
        state: "REOPENED", revision: 4,
        reviewedByUserId: null, decidedAt: null,
      });
      expect(result.review.verification.valid).toBe(true);
      expect(await db.auditEvent.count({ where: {
        organizationId: orgId, resourceId: reviewId,
        action: "assetRetention.review.reopen",
      } })).toBe(1);
    });
    it("never allows a cross-tenant review transition", async () => {
      await expect(transitionAssetRetentionReview(outsider,
        transition("START_REVIEW", 4), now))
        .rejects.toMatchObject({ code: "MISSING" });
      await expect(transitionAssetRetentionReview(member,
        transition("START_REVIEW", 4), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
  });
