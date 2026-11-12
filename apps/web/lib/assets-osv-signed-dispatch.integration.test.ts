import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  consumeSignedDispatch, parseSignedDispatchIntent,
  signOsvDispatch, verifySignedDispatch,
} from "./assets-osv-signed-dispatch";
import { inspectSignedDispatchOperations } from "./assets-osv-dispatch-observability";
import {
  createOsvSchedule, changeOsvSchedule,
} from "./assets-osv-renewal-schedules";
import { importAssetInventory } from "./assets-inventory-service";
import type { AssetScope } from "./assets-inventory-service";

const now = new Date("2026-11-10T12:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV service dispatcher signed request replay and tenant enforcement", () => {
    const nonce = randomUUID().replaceAll("-", "").slice(0, 15);
    const org = "osv-sign-org-" + nonce;
    const other = "osv-sign-other-" + nonce;
    const slug = "osv-sign-slug-" + nonce;
    const adminId = "osv-sign-admin-" + nonce;
    const outsiderId = "osv-sign-outsider-" + nonce;
    const readerId = "osv-sign-reader-" + nonce;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const outsider: AssetScope = {
      organizationId: other, userId: outsiderId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: readerId, role: "MEMBER",
    };
    const secretHex = "f2".repeat(32);
    const key = {
      id: "osv-sign-key-" + nonce, organizationId: org, secretHex,
    };
    let scheduleId = "";
    let revision = 0;
    let importId = "";
    let sourceId = "";
    const config = () => ({
      name: "Signed service dispatcher fixture",
      inventoryImportId: importId,
      sourceInspectionId: sourceId,
      cadenceMinutes: 60,
      inspection: {
        importId, dryRun: true, limitPackages: 5,
        maxPagesPerPackage: 2, maxRecordsPerPackage: 50,
        maxAgeMinutes: 60,
        packageBindings: [{
          inventoryProduct: "Example Package",
          ecosystem: "npm", packageName: "example-package",
        }],
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
    const intent = (candidate = "random-nonce-first-1234567890") =>
      parseSignedDispatchIntent({
        schema: "cyberpilot.assets.osv.signed-dispatch.v1",
        organizationId: org, organizationSlug: slug,
        scheduleId, expectedRevision: revision,
        issuedAt: "2026-11-10T11:59:30.000Z",
        expiresAt: "2026-11-10T12:01:00.000Z",
        nonce: candidate, confirmDispatch: true,
      });
    const verify = (candidate?: string) => {
      const signed = intent(candidate);
      return verifySignedDispatch(signed, key.id,
        signOsvDispatch(signed, secretHex),
        { enabled: true, keys: [key] }, now);
    };
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Signed admin",
          email: "signed-admin-" + nonce + "@example.invalid" },
        { id: outsiderId, name: "Signed foreign admin",
          email: "signed-other-" + nonce + "@example.invalid" },
        { id: readerId, name: "Signed reader",
          email: "signed-reader-" + nonce + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Signed dispatch tenant", slug },
        { id: other, name: "Signed dispatch foreign tenant",
          slug: "osv-sign-other-" + nonce },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: readerId, role: "MEMBER" },
        { organizationId: other, userId: outsiderId, role: "ADMIN" },
      ] });
      const inventory = await importAssetInventory(admin, {
        sourceLabel: "Signed dispatcher fixture",
        idempotencyKey: "signed-fixture-import-" + nonce,
        dryRun: false,
        csv: [
          "asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at",
          "device-001,host-001,,LINUX,Ubuntu,24.04,Example Package,1.2.3,2026-11-01T12:00:00.000Z",
        ].join("\n") + "\n",
      }, new Date("2026-11-09T09:00:00.000Z"));
      importId = inventory.importId!;
      const prior = await db.assetOsvInspection.create({ data: {
        organizationId: org, inventoryImportId: importId,
        requestKey: "signed-prior-" + nonce,
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
      sourceId = prior.id;
      const schedule = await createOsvSchedule(admin,
        config(), new Date("2026-11-10T10:00:00.000Z"));
      scheduleId = schedule.id;
      const enabled = await changeOsvSchedule(admin, {
        scheduleId, expectedRevision: schedule.revision,
        operation: "ENABLE", confirmOutbound: true,
        consentDigest: schedule.consentDigest,
      }, new Date("2026-11-10T10:01:00.000Z"));
      revision = enabled.revision;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, other] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, outsiderId, readerId] } },
      });
    });
    it("consumes one valid tenant-scoped nonce and audits SERVICE actor", async () => {
      const signed = verify();
      await consumeSignedDispatch(signed, now);
      const saved = await db.assetOsvDispatchNonce.findFirstOrThrow({
        where: { organizationId: org,
          nonceDigest: signed.nonceDigest },
      });
      expect(saved.requestDigest).toBe(signed.requestDigest);
      expect(saved.keyId).toBe(key.id);
      expect(await db.auditEvent.count({ where: {
        organizationId: org,
        actorType: "SYSTEM",
        action: "assets.osv.dispatch.signature.accepted",
        resourceId: scheduleId,
      } })).toBe(1);
    });
    it("prevents reuse of the same signed nonce without creating a second audit", async () => {
      await expect(consumeSignedDispatch(verify(), now))
        .rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.assetOsvDispatchNonce.count({
        where: { organizationId: org },
      })).toBe(1);
      expect(await db.auditEvent.count({ where: {
        organizationId: org,
        action: "assets.osv.dispatch.signature.accepted",
      } })).toBe(1);
    });
    it("allows a distinct nonce for the same due slot but never a second claim", async () => {
      const signed = verify("random-nonce-second-1234567890");
      await consumeSignedDispatch(signed, now);
      expect(await db.assetOsvDispatchNonce.count({
        where: { organizationId: org },
      })).toBe(2);
      const diagnostic = await inspectSignedDispatchOperations(
        admin, { lookbackHours: 24 }, now);
      expect(diagnostic.acceptedNoncesInWindow).toBe(2);
      expect(diagnostic.configuration.hasTenantKey).toBe(false);
    });
    it("rejects cross-tenant organization slug and key despite valid HMAC", async () => {
      const signed = verify("random-nonce-third-1234567890");
      await expect(consumeSignedDispatch({
        ...signed, organizationSlug: "osv-sign-other-" + nonce,
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("rejects non-existent schedule and stale revision before consuming nonce", async () => {
      const signed = verify("random-nonce-fourth-1234567890");
      await expect(consumeSignedDispatch({
        ...signed, expectedRevision: revision + 1,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.assetOsvDispatchNonce.count({
        where: { organizationId: org },
      })).toBe(2);
    });
    it("enforces administrative scoping for telemetry", async () => {
      await expect(inspectSignedDispatchOperations(reader, {}, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      const foreign = await inspectSignedDispatchOperations(
        outsider, {}, now);
      expect(foreign.acceptedNoncesInWindow).toBe(0);
      expect(foreign.recent).toEqual([]);
    });
    it("does not reveal any HMAC secrets through operational telemetry", async () => {
      const report = await inspectSignedDispatchOperations(
        admin, {}, now);
      expect(JSON.stringify(report)).not.toContain(secretHex);
      expect(report.recent.every(row =>
        row.requestDigest.length === 64)).toBe(true);
    });
    it("never performs provider queries when only authenticated nonce validation occurs", async () => {
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org },
      })).toBe(0);
      expect(await db.assetOsvQuotaReservation.count({
        where: { organizationId: org },
      })).toBe(0);
      expect(await db.assetOsvInspection.count({
        where: { organizationId: org },
      })).toBe(1);
    });
  },
);
