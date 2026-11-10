import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import {
  createOsvSchedule, changeOsvSchedule, listOsvSchedules,
  previewDueOsvSchedule, executeDueOsvSchedule,
  listOsvScheduleRuns, scheduleConsentDigest,
} from "./assets-osv-renewal-schedules";
import type { AssetScope } from "./assets-inventory-service";
import type { OsvRenewalOutcome } from "./assets-osv-renewal";

const createdAt = new Date("2026-11-09T12:00:00.000Z");
const dueAt = new Date("2026-11-09T14:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV schedule durable permission and worker-claim integration", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 15);
    const org = "osv-scheduler-" + nonce;
    const foreign = "osv-scheduler-foreign-" + nonce;
    const adminId = "osv-scheduler-admin-" + nonce;
    const readerId = "osv-scheduler-reader-" + nonce;
    const outsiderId = "osv-scheduler-outsider-" + nonce;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: readerId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: outsiderId, role: "ADMIN",
    };
    let importId = "";
    let sourceId = "";
    let scheduleId = "";
    let revision = 1;
    const config = () => ({
      name: "Synthetic hourly OSV schedule",
      inventoryImportId: importId,
      sourceInspectionId: sourceId,
      cadenceMinutes: 60,
      inspection: {
        importId, dryRun: true,
        packageBindings: [{
          inventoryProduct: "Example Package",
          ecosystem: "npm", packageName: "example-package",
        }],
        limitPackages: 5, maxPagesPerPackage: 2,
        maxRecordsPerPackage: 50, maxAgeMinutes: 60,
      },
      policy: {
        freshnessMinutes: 60, minimumRetryMinutes: 60,
        maximumQueriesPerDay: 200,
        maximumInspectionsPerDay: 20,
        maximumPackagesPerRun: 5,
        historyWindowDays: 90, includeIncomplete: true,
      },
      allowNewPackages: false,
      allowIncompleteInventory: false,
    });
    const fakeExecute = vi.fn(async (): Promise<OsvRenewalOutcome> => ({
      schema: "cyberpilot.assets.osv.renewal.outcome.v1",
      organizationId: org, importId,
      previousInspectionId: sourceId,
      currentInspectionId: "new-inspection-synthetic-12345",
      replayed: false, status: "COMPLETE",
      newReportDigest: "b".repeat(64),
      previousReportDigest: "a".repeat(64),
      comparison: null, completeComparison: false,
      warnings: ["Synthetic worker execution; not a live OSV API check."],
    }));
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Schedule administrator",
          email: "schedule-admin-" + nonce + "@example.invalid" },
        { id: readerId, name: "Schedule member",
          email: "schedule-member-" + nonce + "@example.invalid" },
        { id: outsiderId, name: "Schedule outsider",
          email: "schedule-outsider-" + nonce + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Schedule tests",
          slug: "schedule-osv-" + nonce },
        { id: foreign, name: "Other schedule tests",
          slug: "schedule-osv-other-" + nonce },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: readerId, role: "MEMBER" },
        { organizationId: foreign, userId: outsiderId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "device-a,host-a,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
        ].join("\n") + "\n",
        sourceLabel: "Schedule synthetic fixture",
        idempotencyKey: "osv-scheduler-import-" + nonce,
        dryRun: false,
      }, createdAt);
      importId = imported.importId!;
      const prior = await db.assetOsvInspection.create({ data: {
        organizationId: org, inventoryImportId: importId,
        requestKey: "scheduler-source-" + nonce,
        requestDigest: "a".repeat(64),
        reportDigest: "a".repeat(64),
        status: "COMPLETE", provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 1, completedCount: 1,
        possibleCount: 0, providerOnlyCount: 0,
        completedAt: new Date("2026-11-01T12:00:00.000Z"),
        report: {
          schema: "cyberpilot.assets.osv.official.inspection.v1",
          organizationId: org, importId,
          status: "COMPLETE", reportDigest: "a".repeat(64),
          coverage: "DECLARED_NOT_VERIFIED", dryRun: false,
          results: [],
        },
        queries: {
          create: [{
            organizationId: org, queryKey: "c".repeat(64),
            ecosystem: "npm", packageName: "example-package",
            version: "1.2.3", providerStatus: "COMPLETE",
            checkedAt: new Date("2026-11-01T12:00:00.000Z"),
            observationCount: 1, pageCount: 1,
            possibleIds: [], providerOnlyIds: [],
            unresolvedIds: [], withdrawnIds: [],
          }],
        },
      } });
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
    it("blocks creation by members without writing schedule definitions", async () => {
      await expect(createOsvSchedule(reader, config(), createdAt))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(await db.assetOsvRenewalSchedule.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("creates a disabled, non-consenting definition and audit event", async () => {
      const stored = await createOsvSchedule(admin, config(), createdAt);
      scheduleId = stored.id; revision = stored.revision;
      expect(stored).toMatchObject({
        enabled: false, outboundConsent: false,
        cadenceMinutes: 60, revision: 1,
      });
      expect(stored.nextDueAt).toBe("2026-11-09T13:00:00.000Z");
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, action: "assets.osv.schedule.created",
          resourceId: scheduleId,
        },
      })).toBe(1);
    });
    it("restricts schedule listing and preview by organization", async () => {
      expect((await listOsvSchedules(admin)).total).toBe(1);
      expect((await listOsvSchedules(outsider)).total).toBe(0);
      await expect(previewDueOsvSchedule(outsider, {
        scheduleId,
      }, dueAt)).rejects.toMatchObject({ code: "MISSING" });
      await expect(listOsvSchedules(reader))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("does not dispatch without consent or before a due slot", async () => {
      await expect(executeDueOsvSchedule(admin, {
        scheduleId, expectedRevision: revision, confirmDispatch: true,
      }, { now: () => dueAt, execute: fakeExecute }))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(fakeExecute).not.toHaveBeenCalled();
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("rejects incorrect consent digest and stale revision", async () => {
      await expect(changeOsvSchedule(admin, {
        scheduleId, expectedRevision: revision,
        operation: "ENABLE", confirmOutbound: true,
        consentDigest: "f".repeat(64),
      }, createdAt)).rejects.toMatchObject({ code: "CONFLICT" });
      const actual = scheduleConsentDigest(org,
        (await import("./assets-osv-renewal-schedules"))
          .parseOsvScheduleConfig(config()));
      const result = await changeOsvSchedule(admin, {
        scheduleId, expectedRevision: revision,
        operation: "ENABLE", confirmOutbound: true,
        consentDigest: actual,
      }, createdAt);
      revision = result.revision;
      expect(result.enabled).toBe(true);
      await expect(changeOsvSchedule(admin, {
        scheduleId, expectedRevision: 1,
        operation: "DISABLE",
        confirmOutbound: false, consentDigest: null,
      }, createdAt)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("previews a due slot without external network calls or claiming", async () => {
      fakeExecute.mockClear();
      const before = await db.assetOsvRenewalRun.count({
        where: { organizationId: org },
      });
      const plan = await previewDueOsvSchedule(admin, {
        scheduleId,
      }, dueAt);
      expect(plan.claimable).toBe(true);
      expect(plan.renewal?.validForExecution).toBe(true);
      expect(plan.renewal?.maximumHttpPages).toBe(2);
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org },
      })).toBe(before);
      expect(fakeExecute).not.toHaveBeenCalled();
    });
    it("claims exactly one slot amid concurrent administrative dispatches", async () => {
      fakeExecute.mockClear();
      const params = {
        scheduleId, expectedRevision: revision, confirmDispatch: true,
      };
      const attempts = await Promise.allSettled([
        executeDueOsvSchedule(admin, params, {
          now: () => dueAt, execute: fakeExecute,
        }),
        executeDueOsvSchedule(admin, params, {
          now: () => dueAt, execute: fakeExecute,
        }),
      ]);
      const success = attempts.filter(result =>
        result.status === "fulfilled");
      const denied = attempts.filter(result =>
        result.status === "rejected");
      expect(success).toHaveLength(1);
      expect(denied).toHaveLength(1);
      expect(fakeExecute).toHaveBeenCalledTimes(1);
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org, scheduleId },
      })).toBe(1);
      const run = await db.assetOsvRenewalRun.findFirstOrThrow({
        where: { organizationId: org, scheduleId },
      });
      expect(run.state).toBe("COMPLETE");
      expect(run.inspectionId).toBe("new-inspection-synthetic-12345");
      expect(run.completedAt).not.toBeNull();
      const changed = await db.assetOsvRenewalSchedule.findUniqueOrThrow({
        where: { id: scheduleId },
      });
      revision = changed.revision;
      expect(changed.nextDueAt).toEqual(
        new Date("2026-11-09T15:00:00.000Z"));
      expect(changed.lastSucceededAt).not.toBeNull();
    });
    it("returns history with one successful claimed slot and bounded metadata", async () => {
      const result = await listOsvScheduleRuns(admin, scheduleId);
      expect(result.total).toBe(1);
      expect(result.runs[0]?.state).toBe("COMPLETE");
      expect(result.runs[0]?.commandDigest)
        .toMatch(/^[a-f0-9]{64}$/);
      await expect(listOsvScheduleRuns(outsider, scheduleId))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("revokes consent and blocks future scheduled dispatches", async () => {
      const disabled = await changeOsvSchedule(admin, {
        scheduleId, expectedRevision: revision, operation: "DISABLE",
        confirmOutbound: false, consentDigest: null,
      }, dueAt);
      revision = disabled.revision;
      expect(disabled.enabled).toBe(false);
      expect(disabled.outboundConsent).toBe(false);
      await expect(executeDueOsvSchedule(admin, {
        scheduleId, expectedRevision: revision, confirmDispatch: true,
      }, { now: () => new Date("2026-11-09T16:00:00.000Z"),
        execute: fakeExecute }))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("keeps every attempt audited and never edits inventory findings", async () => {
      expect(await db.auditEvent.count({
        where: { organizationId: org,
          action: "assets.osv.schedule.run.claimed" },
      })).toBe(1);
      expect(await db.auditEvent.count({
        where: { organizationId: org,
          action: "assets.osv.schedule.run.complete" },
      })).toBe(1);
      expect(await db.assetInventoryDevice.count({
        where: { organizationId: org, importId },
      })).toBe(1);
    });
  },
);
