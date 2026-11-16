import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  ExposurePassiveScheduleService, PassiveScheduleConflict,
} from "./exposure-passive-schedule-service";
import {
  buildPassiveScheduleSummary, verifyPassiveScheduleSummary,
  exportPassiveScheduleSummary,
} from "./exposure-passive-schedule-report";

describe.skipIf(!process.env.DATABASE_URL)(
  "Passive collection policy and durable denied reservations", () => {
    const suffix = randomUUID().slice(0, 8);
    const org = "passive-owner-" + suffix;
    const otherOrg = "passive-outsider-" + suffix;
    const ownerId = "passive-admin-" + suffix;
    const auditorId = "passive-auditor-" + suffix;
    const outsiderId = "passive-other-" + suffix;
    const domain = "example.com";
    const service = new ExposurePassiveScheduleService();
    const owner = {
      organizationId: org, userId: ownerId,
      role: "OWNER" as const,
    };
    const auditor = {
      organizationId: org, userId: auditorId,
      role: "AUDITOR" as const,
    };
    const outsider = {
      organizationId: otherOrg, userId: outsiderId,
      role: "OWNER" as const,
    };
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: ownerId, name: "Passive admin",
          email: "passive-admin-" + suffix + "@example.invalid" },
        { id: auditorId, name: "Passive auditor",
          email: "passive-auditor-" + suffix + "@example.invalid" },
        { id: outsiderId, name: "Passive outsider",
          email: "passive-outsider-" + suffix + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, slug: org, name: "Passive owner" },
        { id: otherOrg, slug: otherOrg,
          name: "Unrelated organization" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: ownerId, role: "OWNER" },
        { organizationId: org, userId: auditorId, role: "AUDITOR" },
        { organizationId: otherOrg, userId: outsiderId,
          role: "OWNER" },
      ] });
      await db.exposureDomainAuthorization.create({
        data: {
          organizationId: org, domain,
          method: "DNS_TOKEN", state: "VERIFIED",
          challengeDigest: "a".repeat(64),
          challengeExpiresAt: new Date(Date.now() + 3600000),
          verifiedAt: new Date(), revision: 2,
          actorUserId: ownerId,
        },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, otherOrg] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [ownerId, auditorId, outsiderId] } },
      });
    });
    it("does not create schedule without authorization", async () => {
      await expect(service.execute(outsider, {
        operation: "CREATE", domain,
        expectedRevision: 0, sources: ["DNS"],
      })).rejects.toThrow();
    });
    it("creates disabled schedule regardless of valid DNS token", async () => {
      const result = await service.execute(owner, {
        operation: "CREATE", domain,
        expectedRevision: 0, sources: ["DNS"],
      });
      const data = result.data as {
        schedule: { state: string; revision: number;
          legalConsentVerified: boolean };
      };
      expect(data.schedule.state).toBe("DISABLED");
      expect(data.schedule.revision).toBe(1);
      expect(data.schedule.legalConsentVerified).toBe(false);
      expect(result.networkRequestsExecuted).toBe(0);
      expect(await db.exposurePassiveEvent.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("rejects auditor mutations but permits scoped inspection", async () => {
      await expect(service.execute(auditor, {
        operation: "PAUSE", domain, expectedRevision: 1,
      })).rejects.toThrow(/administrators/);
      const result = await service.execute(auditor, {
        operation: "LIST", limit: 10,
      });
      expect((result.data as { items: unknown[] }).items)
        .toHaveLength(1);
    });
    it("persists versioned changes and rejects stale writers", async () => {
      const updated = await service.execute(owner, {
        operation: "UPDATE", domain,
        expectedRevision: 1,
        sources: ["DNS","TLS_HANDSHAKE"],
      });
      expect(updated.data).toMatchObject({
        auditWritten: true,
        networkConfigurationActivated: false,
      });
      await expect(service.execute(owner, {
        operation: "UPDATE", domain, expectedRevision: 1,
        sources: ["HTTPS_HEADERS"],
      })).rejects.toBeInstanceOf(PassiveScheduleConflict);
    });
    it("never issues executable quota leases without independent consent", async () => {
      const result = await service.execute(owner, {
        operation: "RESERVE", domain,
        requestId: "passive-reservation-" + suffix,
      });
      const data = result.data as {
        state: string; networkCallsStarted: number;
        rejectionCode: string;
      };
      expect(data.state).toBe("DENIED");
      expect(data.networkCallsStarted).toBe(0);
      expect(data.rejectionCode).toBe("CONSENT_OR_COLLECTOR_NOT_READY");
      const saved = await db.exposurePassiveReservation.findFirstOrThrow({
        where: { organizationId: org },
      });
      expect(saved.reservedDns).toBe(0);
      expect(saved.actualDns).toBe(0);
      expect(saved.actualHttp).toBe(0);
    });
    it("replaying the request ID is idempotent and never allocates quota", async () => {
      const replay = await service.execute(owner, {
        operation: "RESERVE", domain,
        requestId: "passive-reservation-" + suffix,
      });
      expect(replay.data).toMatchObject({
        idempotent: true, state: "DENIED",
        eligibleForNetwork: false,
      });
      expect(await db.exposurePassiveReservation.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("preserves history after a revocation", async () => {
      await service.execute(owner, {
        operation: "REVOKE", domain, expectedRevision: 2,
      });
      const events = await service.execute(auditor, {
        operation: "HISTORY", domain,
      });
      const items = (events.data as {
        events: Array<{ action: string }>;
      }).events;
      expect(items.map(x => x.action))
        .toEqual(["REVOKE","UPDATE","CREATE"]);
    });
    it("separates organization reports and rejects external signed claims", async () => {
      const listed = await service.execute(owner, {
        operation: "LIST",
      });
      const schedules = (listed.data as {
        items: Array<Parameters<typeof buildPassiveScheduleSummary>[1][number]>;
      }).items;
      const report = buildPassiveScheduleSummary(
        org, schedules, new Date().toISOString());
      expect(report.count).toBe(1);
      expect(report.enabledForNetwork).toBe(0);
      expect(verifyPassiveScheduleSummary(report).valid).toBe(true);
      const exported = exportPassiveScheduleSummary(report, "CSV");
      expect(exported.certificationsIssued).toBe(0);
      expect(() => buildPassiveScheduleSummary(otherOrg,
        schedules, new Date().toISOString())).toThrow();
    });
  },
);
