import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import type { AssetScope } from "./assets-inventory-service";
import {
  openAssetAdviceCase, listAssetAdviceCases,
  changeAssetAdviceCase, changeAssetAdviceStep,
} from "./assets-action-case-service";
import { inspectAssetActionGuidance } from "./assets-action-guidance-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "PostgreSQL asset candidate review across evidence and human work", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 15);
    const organizationId = "asset-work-org-" + token;
    const foreignId = "asset-work-foreign-" + token;
    const adminId = "asset-work-admin-" + token;
    const readerId = "asset-work-reader-" + token;
    const outsiderId = "asset-work-outsider-" + token;
    const admin: AssetScope = {
      organizationId, userId: adminId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId, userId: readerId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreignId, userId: outsiderId, role: "ADMIN",
    };
    const bindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
      expectedPurl: null,
    }];
    const now = new Date("2026-11-10T12:00:00.000Z");
    const reason = "Verified the original evidence source and assigned a human investigation.";
    let importId = "";
    let inspectionId = "";
    let fingerprint = "";
    let caseId = "";
    const create = () => ({
      importId, inspectionId, bindings,
      evidenceFingerprint: fingerprint, reason,
    });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Case admin",
          email: "case-admin-" + token + "@example.invalid" },
        { id: readerId, name: "Case reader",
          email: "case-reader-" + token + "@example.invalid" },
        { id: outsiderId, name: "Case outsider",
          email: "case-outside-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: organizationId, name: "Case organization",
          slug: "case-org-" + token },
        { id: foreignId, name: "Foreign case organization",
          slug: "case-outside-" + token },
      ] });
      await db.membership.createMany({ data: [
        { organizationId, userId: adminId, role: "ADMIN" },
        { organizationId, userId: readerId, role: "MEMBER" },
        { organizationId: foreignId, userId: outsiderId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        sourceLabel: "Synthetic advisory review fixture",
        idempotencyKey: "advice-import-" + token,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "host-001,host-001,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-09T10:00:00.000Z",
        ].join("\n") + "\n",
      }, now);
      importId = imported.importId!;
      const inspection = await db.assetOsvInspection.create({ data: {
        organizationId, inventoryImportId: importId,
        requestKey: "case-provider-key-" + token,
        requestDigest: "a".repeat(64),
        reportDigest: "b".repeat(64),
        status: "COMPLETE",
        provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 1, completedCount: 1,
        possibleCount: 1, providerOnlyCount: 0,
        completedAt: now,
        report: { schema: "fixture.synthetic.osv.v1" },
        queries: { create: [{
          organizationId,
          queryKey: "c".repeat(64),
          ecosystem: "npm", packageName: "example-package",
          version: "1.2.3", providerStatus: "COMPLETE",
          providerDigest: "d".repeat(64),
          checkedAt: now, observationCount: 1, pageCount: 1,
          possibleIds: ["GHSA-aaaa-bbbb-cccc"],
          providerOnlyIds: [], withdrawnIds: [], unresolvedIds: [],
        }] },
      } });
      inspectionId = inspection.id;
      const report = await inspectAssetActionGuidance(
        admin, { importId, inspectionId, bindings }, now);
      expect(report.summary.possible).toBe(1);
      fingerprint = report.rows[0]!.evidenceFingerprint;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, foreignId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, readerId, outsiderId] } },
      });
    });
    it("rejects creation by read-only member and cross-tenant administrator", async () => {
      await expect(openAssetAdviceCase(reader, create(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(openAssetAdviceCase(outsider, create(), now))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("recomputes and compares evidence instead of trusting client advisory IDs", async () => {
      await expect(openAssetAdviceCase(admin, {
        ...create(), evidenceFingerprint: "f".repeat(64),
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.assetAdviceCase.count({
        where: { organizationId },
      })).toBe(0);
    });
    it("opens a review case and tracks only the explicit human actions", async () => {
      const result = await openAssetAdviceCase(admin, create(), now);
      expect(result.replayed).toBe(false);
      expect(result.case).toMatchObject({
        organizationId, status: "OPEN",
        category: "REVIEW_POSSIBLE_ADVISORY",
        evidenceFingerprint: fingerprint,
      });
      caseId = result.case.id;
      expect(result.case.steps.length).toBeGreaterThan(0);
      expect(result.case.steps.every(step => step.status === "TODO"))
        .toBe(true);
      expect(await db.auditEvent.count({
        where: {
          organizationId, resourceId: caseId,
          action: "assets.advice.case.opened",
        },
      })).toBe(1);
    });
    it("handles idempotent opening without duplicate audit or work", async () => {
      const result = await openAssetAdviceCase(admin, create(), now);
      expect(result.replayed).toBe(true);
      expect(result.case.id).toBe(caseId);
      expect(await db.assetAdviceCase.count({
        where: { organizationId },
      })).toBe(1);
      expect(await db.auditEvent.count({
        where: {
          organizationId, resourceId: caseId,
          action: "assets.advice.case.opened",
        },
      })).toBe(1);
    });
    it("keeps case list isolated by organization", async () => {
      const theirs = await listAssetAdviceCases(outsider);
      expect(theirs.total).toBe(0);
      const ours = await listAssetAdviceCases(reader);
      expect(ours.total).toBe(1);
      expect(ours.cases[0]!.evidenceFingerprint).toBe(fingerprint);
    });
    it("starts human review with a revision CAS and one audit", async () => {
      const existing = (await listAssetAdviceCases(admin)).cases[0]!;
      await expect(changeAssetAdviceCase(admin, {
        caseId, expectedRevision: existing.revision,
        expectedEvidenceFingerprint: fingerprint,
        operation: "COMPLETE_WORK", reason,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      const result = await changeAssetAdviceCase(admin, {
        caseId, expectedRevision: existing.revision,
        expectedEvidenceFingerprint: fingerprint,
        operation: "START_REVIEW", reason,
      }, now);
      expect(result.case.status).toBe("IN_REVIEW");
      expect(result.remediationVerified).toBe(false);
      expect(result.findingsChanged).toBe(false);
    });
    it("does not mark work complete until every step is DONE", async () => {
      const existing = (await listAssetAdviceCases(admin)).cases[0]!;
      await expect(changeAssetAdviceCase(admin, {
        caseId, expectedRevision: existing.revision,
        expectedEvidenceFingerprint: fingerprint,
        operation: "COMPLETE_WORK", reason,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("records checklist notes and blocks competing stale revisions", async () => {
      const existing = (await listAssetAdviceCases(admin)).cases[0]!;
      const step = existing.steps[0]!;
      const result = await changeAssetAdviceStep(admin, {
        caseId, actionCode: step.actionCode,
        expectedCaseRevision: existing.revision,
        expectedStepRevision: step.revision,
        status: "DONE", note: reason,
      }, now);
      expect(result.case.revision).toBe(existing.revision + 1);
      expect(result.verifiedRemediation).toBe(false);
      await expect(changeAssetAdviceStep(admin, {
        caseId, actionCode: step.actionCode,
        expectedCaseRevision: existing.revision,
        expectedStepRevision: step.revision,
        status: "BLOCKED", note: reason,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("completes documented work without touching finding or CyberScore", async () => {
      let latest = (await listAssetAdviceCases(admin)).cases[0]!;
      for (const step of latest.steps.filter(x => x.status !== "DONE")) {
        const result = await changeAssetAdviceStep(admin, {
          caseId, actionCode: step.actionCode,
          expectedCaseRevision: latest.revision,
          expectedStepRevision: step.revision,
          status: "DONE", note: reason,
        }, now);
        latest = result.case;
      }
      const completed = await changeAssetAdviceCase(admin, {
        caseId, expectedRevision: latest.revision,
        expectedEvidenceFingerprint: fingerprint,
        operation: "COMPLETE_WORK", reason,
      }, now);
      expect(completed.case.status).toBe("WORK_COMPLETED");
      expect(completed.remediationVerified).toBe(false);
      expect(completed.findingsChanged).toBe(false);
      expect(completed.cyberScoreChanged).toBe(false);
      expect(await db.assetOsvInspection.count({
        where: { organizationId },
      })).toBe(1);
    });
    it("records reopen as human review, not a new provider inspection", async () => {
      const latest = (await listAssetAdviceCases(admin)).cases[0]!;
      const reopened = await changeAssetAdviceCase(admin, {
        caseId, expectedRevision: latest.revision,
        expectedEvidenceFingerprint: fingerprint,
        operation: "REOPEN", reason,
      }, now);
      expect(reopened.case.status).toBe("OPEN");
      expect(await db.assetOsvInspection.count({
        where: { organizationId },
      })).toBe(1);
    });
  },
);
