import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { db } from "@cyberpilot/database";
import {
  listDispatchAlerts, scanDispatchAlerts, transitionDispatchAlert,
} from "./assets-osv-dispatch-alerts";
import type { AssetScope } from "./assets-inventory-service";
import type { DispatchOperationalReport } from "./assets-osv-dispatch-observability";

const now = new Date("2026-11-10T12:00:00.000Z");
describe.skipIf(!process.env.DATABASE_URL)(
  "OSV dispatcher incident lifecycle in PostgreSQL", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "dispatch-alert-org-" + token;
    const foreign = "dispatch-alert-other-" + token;
    const adminId = "dispatch-alert-admin-" + token;
    const memberId = "dispatch-alert-member-" + token;
    const outsiderId = "dispatch-alert-outsider-" + token;
    const admin: AssetScope = {
      organizationId: org, userId: adminId, role: "ADMIN",
    };
    const reader: AssetScope = {
      organizationId: org, userId: memberId, role: "MEMBER",
    };
    const outsider: AssetScope = {
      organizationId: foreign, userId: outsiderId, role: "ADMIN",
    };
    let failures = 3;
    const inspect = vi.fn(async (): Promise<DispatchOperationalReport> => ({
      schema: "cyberpilot.assets.osv.signed-dispatch.operations.v1",
      organizationId: org, evaluatedAt: now.toISOString(),
      policy: {
        lookbackHours: 24, maximumRecent: 50,
        alertAfterMinutes: 45, alertFailureThreshold: 3,
        alertUnsettledThreshold: 1,
      },
      configuration: {
        schema: "cyberpilot.assets.osv.signed-dispatch.readiness.v1",
        enabled: false, scopedKeys: 0,
        organizationId: org, eligibleKeyIds: [], hasTenantKey: false,
        replayStorage: "POSTGRESQL",
        maxRequestAgeSeconds: 120, maxClockSkewSeconds: 30,
        grantsScheduleCreation: false,
        grantsConsentModification: false,
        grantsQuotaOverride: false,
        installsCron: false, warnings: [],
      },
      acceptedNoncesInWindow: 0, displayed: 0, truncated: false,
      unmatchedAcceptedNonces: 0, failedClaimsInWindow: failures,
      unknownClaimsInWindow: 0, unsettledClaims: 0,
      oldestUnsettledMinutes: null, recent: [],
      alerts: [{
        code: "DISPATCH_FAILURE_THRESHOLD",
        severity: "CRITICAL",
        summary: "The recent failed run count reached the threshold.",
        action: "Investigate local worker failures before resuming dispatch.",
      }],
      warnings: [],
    }));
    const deps = { inspect };
    const reason = "Reviewed locally recorded worker errors and checked quota state.";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Incident operator",
          email: "alert-admin-" + token + "@example.invalid" },
        { id: memberId, name: "Incident reader",
          email: "alert-reader-" + token + "@example.invalid" },
        { id: outsiderId, name: "Outside operator",
          email: "alert-outsider-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, name: "Incident tenant", slug: "alert-tenant-" + token },
        { id: foreign, name: "Outside tenant",
          slug: "alert-other-" + token },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: adminId, role: "ADMIN" },
        { organizationId: org, userId: memberId, role: "MEMBER" },
        { organizationId: foreign, userId: outsiderId, role: "ADMIN" },
      ] });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, foreign] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, outsiderId] } },
      });
    });
    it("blocks non-admin scans and lists, and isolates foreign tenants", async () => {
      await expect(scanDispatchAlerts(reader, {}, now, deps))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(listDispatchAlerts(reader))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      const other = await listDispatchAlerts(outsider);
      expect(other.total).toBe(0);
      expect(inspect).not.toHaveBeenCalled();
    });
    it("records a new incident and audit event from local-only diagnostics", async () => {
      const result = await scanDispatchAlerts(admin, {}, now, deps);
      expect(result.opened).toBe(1);
      expect(result.updated).toBe(0);
      expect(result.observed).toBe(1);
      const page = await listDispatchAlerts(admin);
      expect(page.total).toBe(1);
      expect(page.alerts[0]).toMatchObject({
        code: "DISPATCH_FAILURE_THRESHOLD",
        state: "OPEN", severity: "CRITICAL",
        revision: 1, observedCount: 1,
      });
      expect(await db.auditEvent.count({
        where: {
          organizationId: org,
          action: "assets.osv.dispatch.alert.opened",
        },
      })).toBe(1);
    });
    it("deduplicates identical evidence without creating another event", async () => {
      const result = await scanDispatchAlerts(admin, {},
        new Date(now.getTime() + 60000), deps);
      expect(result.unchanged).toBe(1);
      expect(result.opened).toBe(0);
      const page = await listDispatchAlerts(admin);
      expect(page.alerts[0]?.observedCount).toBe(1);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org,
          action: "assets.osv.dispatch.alert.opened",
        },
      })).toBe(1);
    });
    it("rejects triage using stale fingerprints, revisions or other tenants", async () => {
      const alert = (await listDispatchAlerts(admin)).alerts[0]!;
      await expect(transitionDispatchAlert(outsider, {
        alertId: alert.id, expectedRevision: alert.revision,
        expectedEvidenceDigest: alert.evidenceDigest,
        operation: "ACKNOWLEDGE", reason,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
      await expect(transitionDispatchAlert(admin, {
        alertId: alert.id, expectedRevision: 777,
        expectedEvidenceDigest: alert.evidenceDigest,
        operation: "ACKNOWLEDGE", reason,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(transitionDispatchAlert(admin, {
        alertId: alert.id, expectedRevision: alert.revision,
        expectedEvidenceDigest: "f".repeat(64),
        operation: "ACKNOWLEDGE", reason,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("does not allow an OPEN alert to be directly RESOLVED", async () => {
      const alert = (await listDispatchAlerts(admin)).alerts[0]!;
      await expect(transitionDispatchAlert(admin, {
        alertId: alert.id, expectedRevision: alert.revision,
        expectedEvidenceDigest: alert.evidenceDigest,
        operation: "RESOLVE", reason,
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("acknowledges with exact operator identity and one immutable audit", async () => {
      const alert = (await listDispatchAlerts(admin)).alerts[0]!;
      const result = await transitionDispatchAlert(admin, {
        alertId: alert.id, expectedRevision: alert.revision,
        expectedEvidenceDigest: alert.evidenceDigest,
        operation: "ACKNOWLEDGE", reason,
      }, now);
      expect(result).toMatchObject({
        auditRecorded: true, providerContacted: false,
        quotaChanged: false, scheduleChanged: false,
      });
      expect(result.alert).toMatchObject({
        state: "ACKNOWLEDGED", revision: 2,
        acknowledgedByUserId: adminId,
        acknowledgementReason: reason,
      });
      expect(await db.auditEvent.count({
        where: {
          organizationId: org,
          resourceId: alert.id,
          action: "assets.osv.dispatch.alert.acknowledge",
        },
      })).toBe(1);
    });
    it("preserves acknowledgement on changed evidence until human resolution", async () => {
      failures = 4;
      const scan = await scanDispatchAlerts(admin, {},
        new Date(now.getTime() + 120000), deps);
      expect(scan.updated).toBe(1);
      expect(scan.retainedAcknowledgements).toBe(1);
      const alert = (await listDispatchAlerts(admin)).alerts[0]!;
      expect(alert).toMatchObject({
        state: "ACKNOWLEDGED", revision: 3,
        observedCount: 2,
        acknowledgedByUserId: adminId,
      });
    });
    it("resolves after investigation without making endpoint security claims", async () => {
      const alert = (await listDispatchAlerts(admin)).alerts[0]!;
      const result = await transitionDispatchAlert(admin, {
        alertId: alert.id, expectedRevision: alert.revision,
        expectedEvidenceDigest: alert.evidenceDigest,
        operation: "RESOLVE", reason,
      }, now);
      expect(result.alert.state).toBe("RESOLVED");
      expect(result.alert.resolvedByUserId).toBe(adminId);
      expect(result.providerContacted).toBe(false);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, resourceId: alert.id,
          action: "assets.osv.dispatch.alert.resolve",
        },
      })).toBe(1);
    });
    it("reopens a resolved alert only on independently changed evidence", async () => {
      failures = 5;
      const result = await scanDispatchAlerts(admin, {},
        new Date(now.getTime() + 240000), deps);
      expect(result.reopened).toBe(1);
      const alert = (await listDispatchAlerts(admin)).alerts[0]!;
      expect(alert).toMatchObject({
        state: "OPEN", revision: 5,
        observedCount: 3, resolutionReason: null,
        acknowledgedByUserId: null,
      });
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, resourceId: alert.id,
          action: "assets.osv.dispatch.alert.reobserved",
        },
      })).toBe(1);
    });
    it("supports tenant-scoped filters and paginated incident reads", async () => {
      const open = await listDispatchAlerts(admin, {
        state: "OPEN", severity: "CRITICAL", limit: 10,
      });
      expect(open.total).toBe(1);
      expect(open.alerts).toHaveLength(1);
      const resolved = await listDispatchAlerts(admin, {
        state: "RESOLVED",
      });
      expect(resolved.total).toBe(0);
      const skipped = await listDispatchAlerts(admin, {
        offset: 10, limit: 1,
      });
      expect(skipped.total).toBe(1);
      expect(skipped.alerts).toEqual([]);
    });
    it("never consumes external OSV quota or mutates inventory during triage", async () => {
      expect(await db.assetOsvQuotaReservation.count({
        where: { organizationId: org },
      })).toBe(0);
      expect(await db.assetOsvInspection.count({
        where: { organizationId: org },
      })).toBe(0);
      expect(await db.assetOsvRenewalRun.count({
        where: { organizationId: org },
      })).toBe(0);
    });
  },
);
