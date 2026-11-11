import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import type { AssetScope } from "./assets-inventory-service";
import {
  createOperatorAcceptanceRun,
  changeOperatorAcceptanceRun,
  listOperatorAcceptanceRuns,
  inspectOperatorRunStatus,
} from "./assets-offline-acceptance-run-service";
import { inspectOfflineCloseoutDossier } from
  "./assets-offline-closeout-dossier";
import { inspectAcceptanceAuditReconciliation } from
  "./assets-acceptance-audit-reconciliation";
import { inspectOperationalCloseout } from
  "./assets-phase4-operational-closeout";

describe.skipIf(!process.env.DATABASE_URL)(
  "PostgreSQL Fase 4 witnessed human closeout and conservative audit", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 15);
    const organizationId = "closeout-org-" + token;
    const foreignId = "closeout-foreign-" + token;
    const adminId = "closeout-admin-" + token;
    const readerId = "closeout-reader-" + token;
    const outsideId = "closeout-outside-" + token;
    const now = new Date("2026-11-11T11:00:00.000Z");
    const admin: AssetScope = {
      organizationId, userId: adminId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId, userId: readerId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreignId, userId: outsideId, role: "ADMIN",
    };
    let importId = "";
    let inspectionId = "";
    let runId = "";
    let dossierDigest = "";
    const reason =
      "Operator performed a bounded assessment of the declared asset evidence.";
    const bindings = [{
      inventoryProduct: "Example Package",
      ecosystem: "npm", packageName: "example-package",
      expectedPurl: null,
    }];
    const source = () => ({
      importId, inspectionId, bindings,
      acceptancePolicy: {}, privacyPolicy: {},
    });
    const command = () => ({
      ...source(),
      idempotencyKey: "closeout-run-" + token,
      reason,
    });
    const change = (operation: string, revision: number,
      extra: Record<string, unknown> = {}) => ({
      bindings, acceptancePolicy: {}, privacyPolicy: {},
      runId, operation,
      expectedRevision: revision,
      expectedDossierDigest: dossierDigest,
      reason, stepCode: null,
      evidenceId: null, evidenceDescription: null,
      limitations: [], acknowledgements: [],
      ...extra,
    });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Closeout operator",
          email: "closeout-admin-" + token + "@example.invalid" },
        { id: readerId, name: "Closeout member",
          email: "closeout-member-" + token + "@example.invalid" },
        { id: outsideId, name: "Closeout outsider",
          email: "closeout-outsider-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: organizationId, slug: "closeout-org-" + token,
          name: "Closeout example organization" },
        { id: foreignId, slug: "closeout-foreign-" + token,
          name: "External closeout organization" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId, userId: adminId, role: "ADMIN" },
        { organizationId, userId: readerId, role: "MEMBER" },
        { organizationId: foreignId, userId: outsideId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        sourceLabel: "Synthetic operator closeout fixture",
        idempotencyKey: "closeout-import-" + token,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "host-001,host-001,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-10T10:00:00.000Z",
        ].join("\n") + "\n",
      }, now);
      importId = imported.importId!;
      const inspection = await db.assetOsvInspection.create({ data: {
        organizationId, inventoryImportId: importId,
        requestKey: "closeout-inspection-" + token,
        requestDigest: "a".repeat(64),
        reportDigest: "b".repeat(64),
        status: "COMPLETE",
        provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 1, completedCount: 1,
        possibleCount: 0, providerOnlyCount: 0,
        completedAt: now,
        report: { schema: "fixture.closeout.osv.v1" },
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
        where: { id: { in: [adminId, readerId, outsideId] } },
      });
    });
    it("builds an end-to-end tenant dossier without changing persistence", async () => {
      const before = await db.auditEvent.count({
        where: { organizationId },
      });
      const dossier = await inspectOfflineCloseoutDossier(
        admin, source(), now);
      expect(dossier).toMatchObject({
        organizationId, importId, inspectionId,
        offlineProductAccepted: false,
        mergeAuthorized: false,
        liveProviderValidated: false,
        destructiveWrites: 0,
      });
      expect(dossier.scenario.passed).toBe(13);
      expect(dossier.release.present).toBe(false);
      expect(dossier.retention.present).toBe(false);
      expect(dossier.counts.blocked).toBeGreaterThan(0);
      expect(await db.auditEvent.count({
        where: { organizationId },
      })).toBe(before);
    });
    it("rejects unauthorized and cross-tenant read-only evaluation", async () => {
      await expect(inspectOfflineCloseoutDossier(
        member, source(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectOfflineCloseoutDossier(
        outsider, source(), now))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("denies unauthenticated operator roles and foreign source IDs", async () => {
      await expect(createOperatorAcceptanceRun(
        member, command(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(createOperatorAcceptanceRun(
        outsider, command(), now))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("creates one DRAFT with atomic event audit and no approval", async () => {
      const created = await createOperatorAcceptanceRun(
        admin, command(), now);
      expect(created.replayed).toBe(false);
      expect(created.run).toMatchObject({
        organizationId, importId,
        inspectionId, revision: 1,
        state: "DRAFT", completedSteps: 0,
        blockedSteps: 0, actualApprovalGranted: false,
      });
      expect(created.run.steps).toHaveLength(9);
      runId = created.run.id;
      dossierDigest = created.run.dossierDigest;
      expect(await db.auditEvent.count({ where: {
        organizationId, resourceId: runId,
        action: "assetAcceptance.run.created",
      } })).toBe(1);
    });
    it("replays the same idempotency key without duplicate audit or state", async () => {
      const repeated = await createOperatorAcceptanceRun(
        admin, command(), now);
      expect(repeated.replayed).toBe(true);
      expect(repeated.run.id).toBe(runId);
      expect(await db.auditEvent.count({ where: {
        organizationId, resourceId: runId,
        action: "assetAcceptance.run.created",
      } })).toBe(1);
      await expect(createOperatorAcceptanceRun(admin, {
        ...command(), importId: "foreign-import",
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("prevents foreign tenants and members from accessing run lists", async () => {
      expect((await listOperatorAcceptanceRuns(admin)).total).toBe(1);
      expect((await listOperatorAcceptanceRuns(outsider)).total).toBe(0);
      await expect(listOperatorAcceptanceRuns(member))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectOperatorRunStatus(outsider, runId, now))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("rejects stale CAS revisions and false evidence digests", async () => {
      await expect(changeOperatorAcceptanceRun(admin,
        change("START", 9), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      await expect(changeOperatorAcceptanceRun(admin,
        change("START", 1, {
          expectedDossierDigest: "f".repeat(64),
        }), now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("opens an operator walkthrough in a transaction", async () => {
      const result = await changeOperatorAcceptanceRun(admin,
        change("START", 1), now);
      expect(result.run).toMatchObject({
        state: "IN_PROGRESS", revision: 2,
        actualApprovalGranted: false,
      });
      dossierDigest = result.run.dossierDigest;
      expect(await db.auditEvent.count({ where: {
        organizationId, resourceId: runId,
        action: "assetAcceptance.run.start",
      } })).toBe(1);
    });
    it("records one witnessed step and audits the exact evidence identifier", async () => {
      const result = await changeOperatorAcceptanceRun(admin,
        change("RECORD_EVIDENCE", 2, {
          stepCode: "CSV_IMPORT_REVIEW",
          evidenceId: "stored-evidence-ref-00001",
          evidenceDescription: "Witnessed validation of the source import.",
        }), now);
      expect(result.run).toMatchObject({
        state: "IN_PROGRESS", revision: 3,
        completedSteps: 1, blockedSteps: 0,
      });
      expect(result.run.steps[0]).toMatchObject({
        status: "EVIDENCE_RECORDED",
        evidenceId: "stored-evidence-ref-00001",
        recordedByUserId: adminId,
      });
      dossierDigest = result.run.dossierDigest;
      expect(await db.auditEvent.count({ where: {
        organizationId, resourceId: runId,
        action: "assetAcceptance.run.record_evidence",
      } })).toBe(1);
    });
    it("rejects incomplete submission without creating a fictitious signoff", async () => {
      await expect(changeOperatorAcceptanceRun(admin,
        change("SUBMIT_FOR_INDEPENDENT_REVIEW", 3), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      const current = await db.assetOfflineAcceptanceRun.findUniqueOrThrow({
        where: { id: runId },
      });
      expect(current).toMatchObject({
        state: "IN_PROGRESS", revision: 3,
        submittedAt: null, submittedByUserId: null,
      });
    });
    it("shows an actual CAS conflict on concurrent writes", async () => {
      const attempts = await Promise.allSettled([
        changeOperatorAcceptanceRun(admin, change("BLOCK_STEP", 3, {
          stepCode: "PRIVACY_AND_PII",
          limitations: ["Responsibility for retention is not signed off"],
        }), now),
        changeOperatorAcceptanceRun(admin, change("BLOCK_STEP", 3, {
          stepCode: "RETENTION_BACKUP_OWNER",
          limitations: ["Backup expiration procedure remains unverified"],
        }), now),
      ]);
      const fulfilled = attempts.filter(r => r.status === "fulfilled");
      const rejected = attempts.filter(r => r.status === "rejected");
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(rejected[0]).toMatchObject({
        reason: { code: "CONFLICT" },
      });
      const succeeded = fulfilled[0] as PromiseFulfilledResult<
        Awaited<ReturnType<typeof changeOperatorAcceptanceRun>>>;
      expect(succeeded.value.run.revision).toBe(4);
      dossierDigest = succeeded.value.run.dossierDigest;
      expect(await db.auditEvent.count({ where: {
        organizationId, resourceId: runId,
        action: "assetAcceptance.run.block_step",
      } })).toBe(1);
    });
    it("reconciles the real PostgreSQL operator audit without signing off", async () => {
      const report = await inspectAcceptanceAuditReconciliation(admin, {
        runId, maximumRunEvents: 100,
        maximumReviewEvents: 100,
      }, now);
      expect(report).toMatchObject({
        organizationId, runId,
        state: "BLOCKED", revision: 4,
        totalRunEvents: 4, totalReviewEvents: 0,
        runAuditComplete: true, reviewAuditComplete: true,
        localAuditIntegrityVerified: true,
        readyForIndependentHumanDecision: false,
        externallySigned: false, legallyApproved: false,
        mergeAuthorized: false, noDatabaseWrites: true,
      });
      await expect(inspectAcceptanceAuditReconciliation(member, {
        runId,
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectAcceptanceAuditReconciliation(outsider, {
        runId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("constructs the real tenant operational closeout without external approval", async () => {
      const before = await db.auditEvent.count({
        where: { organizationId },
      });
      const result = await inspectOperationalCloseout(admin, {
        ...source(), runId, maxAuditEvents: 100,
      }, now);
      expect(result).toMatchObject({
        organizationId, importId, inspectionId,
        operatorRunId: runId,
        localDatabaseWrites: 0,
        liveProviderRequests: 0,
        mergeAuthorized: false,
        legalSignoffVerified: false,
        backupDeletionVerified: false,
      });
      expect(result.overview.blocked).toBeGreaterThan(0);
      expect(result.stages.find(s => s.area === "OPERATOR_WALKTHROUGH")
        ?.state).toBe("BLOCKED");
      expect(result.stages.find(s => s.area === "LIVE_EXCLUSION")
        ?.state).toBe("EXCLUDED");
      expect(await db.auditEvent.count({
        where: { organizationId },
      })).toBe(before);
      await expect(inspectOperationalCloseout(member, {
        ...source(), runId,
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(inspectOperationalCloseout(outsider, {
        ...source(), runId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("rejects a mismatched operator run selection from another import", async () => {
      await expect(inspectOperationalCloseout(admin, {
        ...source(), importId: "other-import-12345", runId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("reconstructs bounded event history and leaves real approvals pending", async () => {
      const result = await inspectOperatorRunStatus(admin, runId, now);
      expect(result).toMatchObject({
        organizationId, run: { revision: 4, state: "BLOCKED" },
        externalSignoffGranted: false,
        phaseClosed: false,
      });
      expect(result.audit.observedCount).toBe(4);
      expect(result.audit.completeWithinBound).toBe(true);
      expect(result.manifest.mergeAuthorized).toBe(false);
      expect(result.manifest.legalApprovalVerified).toBe(false);
    });
  });
