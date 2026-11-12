import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import {
  inspectOsvRotationOperations, parseKeyRotationInput,
} from "./assets-osv-key-rotation";
import type { AssetScope } from "./assets-inventory-service";

const now = new Date("2026-11-10T12:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV key rotation planning is isolated by organization and does not mutate secrets", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 15);
    const org = "osv-rot-org-" + suffix;
    const other = "osv-rot-other-" + suffix;
    const adminId = "osv-rot-admin-" + suffix;
    const memberId = "osv-rot-member-" + suffix;
    const otherId = "osv-rot-outsider-" + suffix;
    const scope: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const member: AssetScope = {
      organizationId: org, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: other, userId: otherId, role: "ADMIN",
    };
    const older = {
      id: "osv-rotation-old-" + suffix,
      organizationId: org, secretHex: "d7".repeat(32),
    };
    const newer = {
      id: "osv-rotation-new-" + suffix,
      organizationId: org, secretHex: "e8".repeat(32),
    };
    const input = () => ({
      organizationId: org, retiringKeyId: older.id,
      replacingKeyId: newer.id,
      effectiveAt: "2026-11-10T13:00:00.000Z",
      retireAt: "2026-11-10T14:00:00.000Z",
      notBefore: "2026-11-10T12:45:00.000Z",
      notAfter: "2026-12-10T14:00:00.000Z",
      policy: {
        minimumOverlapMinutes: 15,
        maximumOverlapMinutes: 1440,
        maximumActiveKeys: 2,
        warningLeadHours: 72,
        requireDistinctMaterial: true,
        requireZeroOutstandingClaims: true,
      },
    });
    const originalFlag = process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED;
    const originalKeys = process.env.CYBERPILOT_OSV_DISPATCH_KEYS;
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Rotation admin",
          email: "osv-rot-admin-" + suffix + "@example.invalid" },
        { id: memberId, name: "Rotation reader",
          email: "osv-rot-reader-" + suffix + "@example.invalid" },
        { id: otherId, name: "Rotation outsider",
          email: "osv-rot-other-" + suffix + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Rotation fixture",
          slug: "osv-rotation-" + suffix },
        { id: other, name: "Rotation foreign",
          slug: "osv-rotation-other-" + suffix },
      ] });
      await db.membership.createMany({ data: [
        { userId: adminId, organizationId: org, role: "ADMIN" },
        { userId: memberId, organizationId: org, role: "MEMBER" },
        { userId: otherId, organizationId: other, role: "ADMIN" },
      ] });
      process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED = "true";
      process.env.CYBERPILOT_OSV_DISPATCH_KEYS =
        JSON.stringify([older, newer]);
    });
    afterAll(async () => {
      if (originalFlag === undefined)
        delete process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED;
      else process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED = originalFlag;
      if (originalKeys === undefined)
        delete process.env.CYBERPILOT_OSV_DISPATCH_KEYS;
      else process.env.CYBERPILOT_OSV_DISPATCH_KEYS = originalKeys;
      await db.organization.deleteMany({
        where: { id: { in: [org, other] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, otherId] } },
      });
    });
    it("rejects unprivileged tenant users before accessing the key inventory", async () => {
      await expect(inspectOsvRotationOperations(
        member, input(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("rejects cross-tenant operators despite their ADMIN role", async () => {
      await expect(inspectOsvRotationOperations(
        outsider, input(), now))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("produces valid overlapping timeline without PostgreSQL writes", async () => {
      const before = await db.auditEvent.count({
        where: { organizationId: org },
      });
      const plan = await inspectOsvRotationOperations(
        scope, input(), now);
      expect(plan.plan).toMatchObject({
        readyForOperatorReview: true,
        activeAtEffective: 2, activeAtRetirement: 1,
        outstandingClaims: 0, unsettledQuotas: 0,
        recentAcceptedNonces: 0,
      });
      expect(plan.noSecretsOrConfigWritten).toBe(true);
      expect(JSON.stringify(plan)).not.toContain(older.secretHex);
      expect(JSON.stringify(plan)).not.toContain(newer.secretHex);
      expect(await db.auditEvent.count({
        where: { organizationId: org },
      })).toBe(before);
    });
    it("does not rewrite installed credentials after generating the proposal", async () => {
      const installed = process.env.CYBERPILOT_OSV_DISPATCH_KEYS;
      const plan = await inspectOsvRotationOperations(
        scope, input(), now);
      expect(plan.plan.changesApplied).toBe(false);
      expect(process.env.CYBERPILOT_OSV_DISPATCH_KEYS)
        .toBe(installed);
      expect(await db.assetOsvDispatchNonce.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("detects unsettled tenant quota without attributing foreign reservations", async () => {
      const quota = await db.assetOsvQuotaDay.create({ data: {
        organizationId: org,
        utcDay: new Date("2026-11-10T00:00:00.000Z"),
        inspectionLimit: 20, requestLimit: 200,
        inspectionsReserved: 1, requestsReserved: 2,
      } });
      // Reserve a synthetic, historical request for policy evaluation only.
      await db.assetOsvQuotaReservation.create({ data: {
        organizationId: org, quotaDayId: quota.id,
        requestKey: "rotation-reservation-" + suffix,
        requestDigest: "a".repeat(64),
        inventoryImportId: "rotation-fixture-no-fetch",
        reservedRequests: 2, state: "RESERVED",
      } });
      const plan = await inspectOsvRotationOperations(
        scope, input(), now);
      expect(plan.plan.unsettledQuotas).toBe(1);
      expect(plan.plan.readyForOperatorReview).toBe(false);
      const foreignReport = await inspectOsvRotationOperations(
        outsider, { ...input(), organizationId: other,
          retiringKeyId: older.id, replacingKeyId: newer.id }, now);
      expect(foreignReport.plan.unsettledQuotas).toBe(0);
      expect(foreignReport.plan.readyForOperatorReview).toBe(false);
    });
  },
);
