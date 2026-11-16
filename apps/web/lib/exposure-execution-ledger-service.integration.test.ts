import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  ExposureExecutionLedgerService, ExecutionLedgerError,
} from "./exposure-execution-ledger-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "Exposure execution ledger PostgreSQL admission and audit", () => {
    const suffix = randomUUID().slice(0, 8);
    const org = "execution-org-" + suffix;
    const other = "execution-outside-" + suffix;
    const ownerId = "execution-owner-" + suffix;
    const auditorId = "execution-auditor-" + suffix;
    const outsiderId = "execution-other-" + suffix;
    const requestId = "request-denied-" + suffix;
    const domain = "example.com";
    const ledger = new ExposureExecutionLedgerService();
    const actor = {
      organizationId: org, userId: ownerId,
      role: "OWNER" as const,
    };
    const auditor = {
      organizationId: org, userId: auditorId,
      role: "AUDITOR" as const,
    };
    const outsider = {
      organizationId: other, userId: outsiderId,
      role: "OWNER" as const,
    };
    const denied = {
      requestId, domain,
      scheduleId: "schedule-unused-" + suffix,
      authorizationId: "authorization-unused-" + suffix,
      authorizationRevision: 1,
      reason: "INDEPENDENT_CONSENT_UNAVAILABLE",
    };
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: ownerId, name: "Execution owner",
          email: "execution-owner-" + suffix + "@example.invalid" },
        { id: auditorId, name: "Execution reviewer",
          email: "execution-auditor-" + suffix + "@example.invalid" },
        { id: outsiderId, name: "Foreign owner",
          email: "execution-outside-" + suffix + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: org, slug: org, name: "Execution tenant" },
        { id: other, slug: other, name: "Foreign execution tenant" },
      ] });
      await db.membership.createMany({ data: [
        { organizationId: org, userId: ownerId, role: "OWNER" },
        { organizationId: org, userId: auditorId, role: "AUDITOR" },
        { organizationId: other, userId: outsiderId, role: "OWNER" },
      ] });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, other] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [ownerId, auditorId, outsiderId] } },
      });
    });
    it("cannot issue executable leases without independent authority", async () => {
      await expect(ledger.issueWithAuthority(actor, {
        requestId: "request-issue-" + suffix,
        organizationId: org, domain,
        scheduleId: denied.scheduleId,
        authorizationId: denied.authorizationId,
        authorizationRevision: 1,
        consentReport: {} as never,
        requiredSources: ["DNS"],
        quotas: { DNS: 1, TLS_HANDSHAKE: 0, HTTPS_HEADERS: 0 },
        maxTotal: 1,
        expiresAt: new Date(Date.now()+120000).toISOString(),
        actorUserId: ownerId,
      })).rejects.toMatchObject({
        code: "INDEPENDENT_EXECUTION_AUTHORITY_UNAVAILABLE",
      });
      expect(await db.exposureExecutionLease.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("cannot consume charges without independent authority", async () => {
      await expect(ledger.consumeWithAuthority({
        organizationId: org, leaseId: "lease-unknown",
        source: "DNS", sequence: 1,
        targetDigest: "a".repeat(64),
        at: new Date().toISOString(),
      })).rejects.toBeInstanceOf(ExecutionLedgerError);
      expect(await db.exposureExecutionCharge.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("records a denied executable request with zero quota", async () => {
      const output = await ledger.recordDenied(actor, denied);
      expect(output.alreadyExists).toBe(false);
      expect(output.lease.state).toBe("DENIED");
      expect(output.lease.quota.totalUsed).toBe(0);
      expect(output.lease.quota.reserved.DNS).toBe(0);
      expect(output.lease.finishedAt).not.toBeNull();
      expect(await db.exposureExecutionLease.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("makes denied requests idempotent and enforces scope", async () => {
      const replay = await ledger.recordDenied(actor, denied);
      expect(replay.alreadyExists).toBe(true);
      await expect(ledger.recordDenied(actor, {
        ...denied, domain: "different.com",
      })).rejects.toMatchObject({
        code: "IDEMPOTENCY_SCOPE_COLLISION",
      });
      expect(await db.exposureExecutionLease.count({
        where: { organizationId: org },
      })).toBe(1);
    });
    it("allows scoped read-only auditor inspection", async () => {
      const read = await ledger.list(auditor, 20);
      expect(read.totalReservations).toBe(1);
      expect(read.denied).toBe(1);
      expect(read.sourceConsumption.DNS).toBe(0);
      expect(read.externalNetworkCallsPerformedByReader).toBe(0);
      expect(read.auditIntegrityIssues).toEqual([]);
      const lease = read.leases[0]!;
      const detail = await ledger.read(auditor,lease.id);
      expect(detail.lease.state).toBe("DENIED");
      expect(detail.charges).toHaveLength(0);
    });
    it("rejects tenant crossover, even with known lease ID", async () => {
      const read = await ledger.list(auditor);
      const id = read.leases[0]!.id;
      await expect(ledger.read(outsider,id)).rejects.toMatchObject({
        code: "LEASE_NOT_FOUND_IN_TENANT",
      });
      const foreign = await ledger.list(outsider);
      expect(foreign.leases).toHaveLength(0);
    });
    it("rejects an auditor from mutating durable requests", async () => {
      await expect(ledger.recordDenied(auditor, {
        ...denied, requestId: "denied-auditor-" + suffix,
      })).rejects.toMatchObject({
        code: "ADMIN_PERMISSION_REQUIRED",
      });
    });
    it("keeps charges impossible on DENIED leases", async () => {
      const lease = (await ledger.list(actor)).leases[0]!;
      await expect(ledger.consumeWithAuthority({
        organizationId: org, leaseId: lease.id,
        source: "DNS", sequence: 1,
        targetDigest: "c".repeat(64),
        at: new Date().toISOString(),
      })).rejects.toMatchObject({
        code: "INDEPENDENT_EXECUTION_AUTHORITY_UNAVAILABLE",
      });
      const still = await ledger.read(actor,lease.id);
      expect(still.lease.state).toBe("DENIED");
      expect(still.charges).toHaveLength(0);
    });
    it("finds anomalous charge counts in a pure reconciliation", async () => {
      const original = (await ledger.list(actor)).leases[0]!;
      const fake = { ...original,
        quota: {
          ...original.quota,
          used: { ...original.quota.used, DNS: 1 },
        },
      };
      expect(ledger.checkLedger([fake],[
        {
          id: "charge-first",
          leaseId: fake.id, organizationId: org,
          sequence: 1, source: "DNS",
          status: "RESERVED", targetDigest: "a".repeat(64),
          resultDigest: null, peerDigest: null, errorCode: null,
          startedAt: new Date().toISOString(), finishedAt: null,
          networkOperationNotInferredFromRecord: true,
        },
      ])).toContain("DENIED_LEASE_WITH_TRAFFIC");
    });
  },
);
