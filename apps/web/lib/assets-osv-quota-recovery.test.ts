import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  parseOsvQuotaRecoveryPolicy, parseOsvQuotaRecoveryCommand,
  assessStalledReservation, previewOsvQuotaRecovery,
  markStalledOsvQuotaUnknown,
} from "./assets-osv-quota-recovery";
import {
  createOsvQuotaCommand, reserveOfficialOsvQuota,
  inspectOfficialOsvQuota,
} from "./assets-osv-atomic-quota";
import type { AssetScope } from "./assets-inventory-service";
const now = new Date("2026-11-09T15:00:00.000Z");
describe("OSV quota recovery policy", () => {
  it("requires a minimum delay and bounded history", () => {
    expect(parseOsvQuotaRecoveryPolicy({})).toEqual({
      minimumAgeMinutes: 30, maximumListed: 50,
    });
    expect(() => parseOsvQuotaRecoveryPolicy({
      minimumAgeMinutes: 1,
    })).toThrow();
    expect(() => parseOsvQuotaRecoveryPolicy({
      maximumListed: 101,
    })).toThrow();
    expect(() => parseOsvQuotaRecoveryPolicy({
      unknown: true,
    })).toThrow();
  });
  it("requires exact double confirmation, reason and digest", () => {
    const item = {
      reservationId: "reservation-12345",
      confirmReservationId: "reservation-12345",
      expectedRequestDigest: "a".repeat(64),
      minimumAgeMinutes: 30,
      reason: "Provider response was lost after a worker interruption.",
    };
    expect(parseOsvQuotaRecoveryCommand(item)).toMatchObject(item);
    expect(() => parseOsvQuotaRecoveryCommand({
      ...item, confirmReservationId: "different",
    })).toThrow();
    expect(() => parseOsvQuotaRecoveryCommand({
      ...item, reason: "short",
    })).toThrow();
    expect(() => parseOsvQuotaRecoveryCommand({
      ...item, expectedRequestDigest: "bad",
    })).toThrow();
  });
  it("never classifies young or terminal reservations as recoverable", () => {
    const old = {
      id: "reservation-12345", requestKey: "key-12345",
      requestDigest: "a".repeat(64),
      inventoryImportId: "import-12345", state: "RESERVED",
      startedAt: new Date(now.getTime() - 3600000),
      reservedRequests: 3,
    };
    expect(assessStalledReservation(old, now, 30).eligible).toBe(true);
    expect(assessStalledReservation({
      ...old, startedAt: new Date(now.getTime() - 60000),
    }, now, 30).eligible).toBe(false);
    expect(assessStalledReservation({
      ...old, state: "FINISHED",
    }, now, 30).eligible).toBe(false);
    expect(assessStalledReservation({
      ...old, startedAt: new Date(now.getTime() + 60000),
    }, now, 30).eligible).toBe(false);
  });
});
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV stale reservation recovery in PostgreSQL", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "recover-osv-" + suffix;
    const foreign = "recover-other-" + suffix;
    const adminId = "recover-admin-" + suffix;
    const otherId = "recover-other-user-" + suffix;
    const readerId = "recover-reader-" + suffix;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: otherId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: readerId, role: "MEMBER",
    };
    const policy = {
      dailyInspectionLimit: 5, dailyRequestLimit: 20,
      maxReservedRequestsPerInspection: 5,
    };
    let reservationId = "";
    let requestDigest = "";
    const reason = "Interrupted worker had uncertain OSV upstream outcome.";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Quota recovery admin",
          email: "recover-admin-" + suffix + "@example.invalid" },
        { id: otherId, name: "Quota recovery other",
          email: "recover-other-" + suffix + "@example.invalid" },
        { id: readerId, name: "Quota recovery reader",
          email: "recover-reader-" + suffix + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Quota recovery organization",
          slug: "recover-osv-" + suffix },
        { id: foreign, name: "Quota recovery outsider",
          slug: "recover-other-" + suffix },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: readerId, role: "MEMBER" },
        { organizationId: foreign, userId: otherId, role: "ADMIN" },
      ] });
      const command = createOsvQuotaCommand(org,
        "import-recovery-12345", 1, 3, "recover-key-" + suffix);
      requestDigest = command.requestDigest;
      const reservation = await reserveOfficialOsvQuota(admin, command,
        new Date(now.getTime() - 3600000), policy);
      reservationId = reservation.reservationId;
      await db.assetOsvQuotaReservation.update({
        where: { id: reservationId },
        data: { startedAt: new Date(now.getTime() - 3600000) },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, otherId, readerId] } },
      });
    });
    const command = () => ({
      reservationId, confirmReservationId: reservationId,
      expectedRequestDigest: requestDigest,
      minimumAgeMinutes: 30, reason,
    });
    it("rejects unauthenticated tenant readers before any recovery", async () => {
      await expect(previewOsvQuotaRecovery(reader, {}, now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(markStalledOsvQuotaUnknown(reader,
        command(), now)).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("does not reveal another organization reservation", async () => {
      await expect(markStalledOsvQuotaUnknown(outsider,
        command(), now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("previews recoverable unknown provider outcomes without writes", async () => {
      const before = await db.assetOsvQuotaReservation.findUniqueOrThrow({
        where: { id: reservationId },
      });
      const preview = await previewOsvQuotaRecovery(admin, {
        minimumAgeMinutes: 30,
      }, now);
      expect(preview.eligible).toBe(1);
      expect(preview.reservations[0]?.id).toBe(reservationId);
      const after = await db.assetOsvQuotaReservation.findUniqueOrThrow({
        where: { id: reservationId },
      });
      expect(after.state).toBe(before.state);
    });
    it("refuses incorrect digest and excessive freshness thresholds", async () => {
      await expect(markStalledOsvQuotaUnknown(admin, {
        ...command(), expectedRequestDigest: "b".repeat(64),
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(markStalledOsvQuotaUnknown(admin, {
        ...command(), minimumAgeMinutes: 300,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("marks a stale reservation UNKNOWN and writes an audit event", async () => {
      const result = await markStalledOsvQuotaUnknown(admin,
        command(), now);
      expect(result.state).toBe("UNKNOWN");
      expect(result.changed).toBe(true);
      expect(result.effectiveRefund).toBe(0);
      const record = await db.assetOsvQuotaReservation.findUniqueOrThrow({
        where: { id: reservationId },
      });
      expect(record.state).toBe("UNKNOWN");
      expect(record.reservedRequests).toBe(3);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org,
          action: "assets.osv.quota.reservation.unknown",
          resourceId: reservationId,
        },
      })).toBe(1);
    });
    it("is idempotent for repeated unknown classifications", async () => {
      const repeated = await markStalledOsvQuotaUnknown(admin,
        command(), now);
      expect(repeated.changed).toBe(false);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org,
          action: "assets.osv.quota.reservation.unknown",
          resourceId: reservationId,
        },
      })).toBe(1);
    });
    it("never refunds reserved capacity after marking the result unknown", async () => {
      const snapshot = await inspectOfficialOsvQuota(admin,
        new Date(now.getTime() - 3600000));
      expect(snapshot.requestsReserved).toBe(3);
      expect(snapshot.inspectionsReserved).toBe(1);
    });
  },
);
