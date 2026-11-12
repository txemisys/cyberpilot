import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { importAssetInventory } from "./assets-inventory-service";
import {
  previewStalledOsvRuns, markStalledOsvRunUnknown,
} from "./assets-osv-run-recovery";
import {
  inspectOsvWorkerReadiness,
} from "./assets-osv-worker-readiness";
import {
  createOsvSchedule, changeOsvSchedule,
  scheduleRunIdempotencyKey,
} from "./assets-osv-renewal-schedules";
import type { AssetScope } from "./assets-inventory-service";

const now = new Date("2026-11-10T12:00:00.000Z");
const hour = 3600000;
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV run recovery: PostgreSQL incident and tenant isolation", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "osv-run-incident-" + nonce;
    const foreign = "osv-incident-foreign-" + nonce;
    const actorId = "osv-incident-actor-" + nonce;
    const memberId = "osv-incident-member-" + nonce;
    const strangerId = "osv-incident-stranger-" + nonce;
    const admin: AssetScope = {
      organizationId: org, userId: actorId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId: org, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: strangerId, role: "ADMIN",
    };
    let importId = "";
    let inspectionId = "";
    let scheduleId = "";
    let runId = "";
    let commandDigest = "";
    const slotAt = new Date("2026-11-10T09:00:00.000Z");
    const reason = "The web worker stopped after outbound network status became uncertain.";
    const config = () => ({
      name: "OSV incident integration policy",
      inventoryImportId: importId,
      sourceInspectionId: inspectionId,
      cadenceMinutes: 1440,
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
        freshnessMinutes: 1440, minimumRetryMinutes: 60,
        maximumQueriesPerDay: 200,
        maximumInspectionsPerDay: 20,
        maximumPackagesPerRun: 5,
        historyWindowDays: 90, includeIncomplete: true,
      },
      allowNewPackages: false,
      allowIncompleteInventory: false,
    });
    const command = () => ({
      runId, confirmRunId: runId,
      expectedCommandDigest: commandDigest,
      minimumExpiredMinutes: 30,
      reason, acknowledgeUnknownNetwork: true,
    });
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: actorId, name: "Incident admin",
          email: "incident-admin-" + nonce + "@example.invalid" },
        { id: memberId, name: "Incident member",
          email: "incident-member-" + nonce + "@example.invalid" },
        { id: strangerId, name: "Incident foreign admin",
          email: "incident-outsider-" + nonce + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Run recovery fixture",
          slug: "run-incident-" + nonce },
        { id: foreign, name: "Foreign run recovery",
          slug: "run-incident-other-" + nonce },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: actorId, role: "ADMIN" },
        { organizationId: org, userId: memberId, role: "MEMBER" },
        { organizationId: foreign, userId: strangerId, role: "ADMIN" },
      ] });
      const imported = await importAssetInventory(admin, {
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "host-001,srv-01,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
        ].join("\n") + "\n",
        sourceLabel: "OSV recovery synthetic fixture",
        idempotencyKey: "osv-incident-import-" + nonce,
        dryRun: false,
      }, now);
      importId = imported.importId!;
      const prior = await db.assetOsvInspection.create({ data: {
        organizationId: org, inventoryImportId: importId,
        requestKey: "osv-incident-prior-" + nonce,
        requestDigest: "a".repeat(64), reportDigest: "b".repeat(64),
        status: "COMPLETE", provider: "OSV_DEV_API",
        coverage: "DECLARED_NOT_VERIFIED",
        queryCount: 1, completedCount: 1,
        possibleCount: 0, providerOnlyCount: 0,
        completedAt: new Date("2026-11-01T12:00:00.000Z"),
        report: {
          schema: "cyberpilot.assets.osv.official.inspection.v1",
          dryRun: false, status: "COMPLETE",
          reportDigest: "b".repeat(64),
          coverage: "DECLARED_NOT_VERIFIED",
          organizationId: org, importId, results: [],
        },
        queries: { create: [{
          organizationId: org, queryKey: "c".repeat(64),
          ecosystem: "npm", packageName: "example-package",
          version: "1.2.3", providerStatus: "COMPLETE",
          providerDigest: "d".repeat(64),
          checkedAt: new Date("2026-11-01T12:00:00.000Z"),
          observationCount: 1, pageCount: 1,
          possibleIds: [], providerOnlyIds: [],
          unresolvedIds: [], withdrawnIds: [],
        }] },
      } });
      inspectionId = prior.id;
      const schedule = await createOsvSchedule(
        admin, config(), new Date("2026-11-01T12:00:00.000Z"));
      scheduleId = schedule.id;
      await changeOsvSchedule(admin, {
        scheduleId, expectedRevision: schedule.revision,
        operation: "ENABLE", confirmOutbound: true,
        consentDigest: schedule.consentDigest,
      }, new Date("2026-11-02T12:00:00.000Z"));
      commandDigest = "e".repeat(64);
      const run = await db.assetOsvRenewalRun.create({ data: {
        organizationId: org, scheduleId,
        slotAt, state: "CLAIMED", commandDigest,
        claimToken: "f".repeat(64),
        claimExpiresAt: new Date(now.getTime() - hour),
        claimedAt: new Date(now.getTime() - 2 * hour),
        requestedByUserId: actorId,
      } });
      runId = run.id;
      await db.assetOsvQuotaDay.create({ data: {
        organizationId: org,
        utcDay: new Date("2026-11-10T00:00:00.000Z"),
        inspectionLimit: 20, requestLimit: 200,
        inspectionsReserved: 1, requestsReserved: 2,
        reservations: { create: [{
          organizationId: org,
          requestKey: "osv-ledger-" +
            scheduleRunIdempotencyKey(scheduleId, slotAt),
          inventoryImportId: importId,
          requestDigest: "a".repeat(64),
          reservedRequests: 2, state: "RESERVED",
        }] },
      } });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [actorId, memberId, strangerId] } },
      });
    });
    it("denies incident access to members and other organizations", async () => {
      await expect(previewStalledOsvRuns(member, {}, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(markStalledOsvRunUnknown(member, command(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(markStalledOsvRunUnknown(outsider, command(), now))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("previews a stalled claim and provider quota without writing", async () => {
      const before = await db.assetOsvRenewalRun.findUniqueOrThrow({
        where: { id: runId },
      });
      const preview = await previewStalledOsvRuns(admin, {
        minimumExpiredMinutes: 30,
      }, now);
      expect(preview.eligible).toBe(1);
      expect(preview.candidates[0]?.runId).toBe(runId);
      expect(preview.candidates[0]?.associatedQuotaState).toBe("RESERVED");
      expect(preview.candidates[0]?.associatedQuotaRequests).toBe(2);
      expect(preview.candidates[0]?.sourceRequestKey).toBe(
        scheduleRunIdempotencyKey(scheduleId, slotAt));
      expect((await db.assetOsvRenewalRun.findUniqueOrThrow({
        where: { id: runId },
      })).state).toBe(before.state);
    });
    it("identifies outstanding runs in readiness but does not authorize a worker", async () => {
      const report = await inspectOsvWorkerReadiness(admin, {}, now);
      expect(report.automationReady).toBe(false);
      expect(report.externalWorkerInstalled).toBe(false);
      expect(report.stalledRunCount).toBe(1);
      expect(report.unsettledQuotaCount).toBe(1);
      expect(report.manualDispatchCandidates.length).toBe(1);
      expect(report.manualDispatchCandidates[0]?.blockingReasons.join(" "))
        .toMatch(/quota/i);
    });
    it("rejects premature and mismatched fingerprint recovery", async () => {
      await expect(markStalledOsvRunUnknown(admin, {
        ...command(), expectedCommandDigest: "f".repeat(64),
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(markStalledOsvRunUnknown(admin, {
        ...command(), minimumExpiredMinutes: 300,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      expect((await db.assetOsvRenewalRun.findUniqueOrThrow({
        where: { id: runId },
      })).state).toBe("CLAIMED");
    });
    it("atomically records UNKNOWN with exactly one incident audit event", async () => {
      const attempts = await Promise.allSettled([
        markStalledOsvRunUnknown(admin, command(), now),
        markStalledOsvRunUnknown(admin, command(), now),
      ]);
      expect(attempts.filter(x => x.status === "fulfilled" ||
        (x.status === "rejected" && x.reason instanceof Error))).toHaveLength(2);
      const run = await db.assetOsvRenewalRun.findUniqueOrThrow({
        where: { id: runId },
      });
      expect(run.state).toBe("UNKNOWN");
      expect(run.errorCode).toBe("WORKER_OUTCOME_UNKNOWN");
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, resourceId: runId,
          action: "assets.osv.schedule.run.unknown",
        },
      })).toBe(1);
    });
    it("does not release the original slot or refund provider budget", async () => {
      const quota = await db.assetOsvQuotaDay.findUniqueOrThrow({
        where: { organizationId_utcDay: {
          organizationId: org,
          utcDay: new Date("2026-11-10T00:00:00.000Z"),
        } },
      });
      expect(quota.requestsReserved).toBe(2);
      expect(quota.inspectionsReserved).toBe(1);
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org, scheduleId, slotAt },
      })).toBe(1);
    });
    it("treats a previously classified UNKNOWN run idempotently", async () => {
      const duplicate = await markStalledOsvRunUnknown(admin, command(), now);
      expect(duplicate.changed).toBe(false);
      expect(duplicate.quotaRefunded).toBe(false);
      expect(duplicate.slotReleased).toBe(false);
      expect(duplicate.providerRetried).toBe(false);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, resourceId: runId,
          action: "assets.osv.schedule.run.unknown",
        },
      })).toBe(1);
    });
    it("continues to report an unresolved provider quota after classification", async () => {
      const report = await inspectOsvWorkerReadiness(admin, {}, now);
      expect(report.stalledRunCount).toBe(0);
      expect(report.unknownRunCount).toBe(1);
      expect(report.unsettledQuotaCount).toBe(1);
    });
  },
);
