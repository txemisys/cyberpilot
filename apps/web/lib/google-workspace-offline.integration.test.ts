import { randomUUID } from "node:crypto";
import { describe, beforeAll, afterAll, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  normalizeBatch, type GoogleLabScope,
} from "@cyberpilot/integrations/google-workspace";
import { GoogleOfflineWorkspace } from "./google-workspace-offline-workspace";
import { PrismaGoogleLabRepository,
  assertLabAuditCoherence } from "./google-lab-prisma-repository";

describe.skipIf(!process.env.DATABASE_URL)(
  "Google Workspace LAB PostgreSQL tenant and source integration", () => {
    const token = randomUUID().replaceAll("-", "").slice(0, 14);
    const organizationId = "google-it-" + token;
    const outsideOrg = "google-out-" + token;
    const adminId = "google-admin-" + token;
    const memberId = "google-member-" + token;
    const outsiderId = "google-outsider-" + token;
    const connectionId = "google-connection-" + token;
    const now = "2026-11-12T10:00:00.000Z";
    const nonce = "long-safe-lab-nonce-123456789012345678901234";
    const admin: GoogleLabScope = {
      organizationId, actorUserId: adminId, role: "ADMIN",
    };
    const member: GoogleLabScope = {
      organizationId, actorUserId: memberId, role: "MEMBER",
    };
    const outsider: GoogleLabScope = {
      organizationId: outsideOrg, actorUserId: outsiderId,
      role: "ADMIN",
    };
    const workspace = new GoogleOfflineWorkspace();
    const call = (scope: GoogleLabScope, operation: string, input: unknown) =>
      workspace.execute(scope, { operation, input }, new Date(now));
    let revision = 0;
    let headDigest = "";
    let snapshotId = "";
    beforeAll(async () => {
      await db.user.createMany({ data: [
        { id: adminId, name: "Google LAB admin",
          email: "google-admin-" + token + "@example.invalid" },
        { id: memberId, name: "Google LAB member",
          email: "google-member-" + token + "@example.invalid" },
        { id: outsiderId, name: "Google LAB outsider",
          email: "google-outsider-" + token + "@example.invalid" },
      ] });
      await db.organization.createMany({ data: [
        { id: organizationId, name: "Google LAB first",
          slug: "google-lab-" + token },
        { id: outsideOrg, name: "Google LAB outside",
          slug: "google-out-" + token },
      ] });
      await db.membership.createMany({ data: [
        { organizationId, userId: adminId, role: "ADMIN" },
        { organizationId, userId: memberId, role: "MEMBER" },
        { organizationId: outsideOrg, userId: outsiderId,
          role: "ADMIN" },
      ] });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, outsideOrg] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, outsiderId] } },
      });
    });
    it("creates a tenant-scoped LAB state without touching Google", async () => {
      const created = await call(admin, "CREATE_LAB", {
        connectionId, createdAt: now,
        requestKey: "create-google-" + token,
      });
      expect(created.boundaries.externalGoogleRequests).toBe(0);
      const response = created.data as {
        connection: { state: string; stateDigest: string };
      };
      expect(response.connection.state).toBe("NOT_CONFIGURED");
      expect(response.connection.stateDigest).toMatch(/^[a-f0-9]{64}$/);
      const stored = await db.googleLabConnection.count({
        where: { organizationId, id: connectionId },
      });
      expect(stored).toBe(1);
    });
    it("rejects member LAB changes and foreign-tenant connection reads", async () => {
      await expect(call(member, "MUTATE_LAB", {
        connectionId, expectedRevision: 0,
        type: "ISSUE_CHALLENGE", at: now,
        reason: "Request denied for member.",
        challengeNonce: nonce,
        requestedCapabilities: ["DIRECTORY_USERS"],
      })).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(call(outsider, "GET_LAB", {
        connectionId,
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("persists a challenge, then verifies LAB-only consent and CAS chain", async () => {
      const issued = await call(admin, "MUTATE_LAB", {
        connectionId, expectedRevision: revision,
        type: "ISSUE_CHALLENGE",
        at: "2026-11-12T10:01:00.000Z",
        reason: "Fixture-only user inventory.",
        challengeNonce: nonce,
        requestedCapabilities: [
          "DIRECTORY_USERS", "USER_MFA_ATTRIBUTES",
        ],
      });
      const receipt = (issued.data as {
        receipt: { eventDigest: string; revision: number };
      }).receipt;
      revision = receipt.revision;
      headDigest = receipt.eventDigest;
      expect(revision).toBe(1);
      const accepted = await call(admin, "MUTATE_LAB", {
        connectionId, expectedRevision: revision,
        type: "ACCEPT_LAB", previousEventDigest: headDigest,
        at: "2026-11-12T10:02:00.000Z",
        reason: "Accepted offline synthetic fixture only.",
        challengeNonce: nonce,
      });
      const acceptedReceipt = (accepted.data as {
        receipt: { eventDigest: string; revision: number };
      }).receipt;
      revision = acceptedReceipt.revision;
      headDigest = acceptedReceipt.eventDigest;
      expect(revision).toBe(2);
      const reconciled = await assertLabAuditCoherence(
        admin, connectionId);
      expect(reconciled.valid).toBe(true);
      const events = await db.googleLabEvent.count({
        where: { organizationId, connectionId },
      });
      expect(events).toBe(2);
    });
    it("stores only synthetic normalized assessments and reports", async () => {
      const observation = normalizeBatch({
        organizationId, checkedAt:
          "2026-11-12T10:03:00.000Z",
        source: "SYNTHETIC_FIXTURE",
        users: [{
          id: "fixture-user-one",
          primaryEmail: "sensitive@example.invalid",
          suspended: false, isAdmin: true,
          isEnrolledIn2Sv: false,
          isEnforcedIn2Sv: false,
        }],
        coverage: {
          DIRECTORY_USERS: "AVAILABLE",
          USER_MFA_ATTRIBUTES: "AVAILABLE",
        },
      });
      const result = await call(admin, "SAVE_FIXTURE", {
        connectionId,
        expectedConnectionRevision: revision,
        createdAt: "2026-11-12T10:04:00.000Z",
        retentionDays: 30, observation,
      });
      const row = result.data as {
        summary: { id: string; sourceDigest: string };
        created: boolean;
      };
      snapshotId = row.summary.id;
      expect(row.created).toBe(true);
      const persisted = await db.googleEvidenceSnapshot.findFirstOrThrow({
        where: { id: snapshotId, organizationId },
      });
      expect(JSON.stringify(persisted.assessment))
        .not.toContain("sensitive@example.invalid");
      expect(JSON.stringify(persisted.report))
        .not.toContain("sensitive@example.invalid");
      expect(persisted.sourceType).toBe("SYNTHETIC_FIXTURE");
    });
    it("rejects stored snapshots outside the requested tenant", async () => {
      await expect(call(outsider, "READ_SNAPSHOT", {
        snapshotId,
      })).rejects.toMatchObject({ code: "MISSING" });
      const result = await call(member, "READ_SNAPSHOT", {
        snapshotId,
      });
      expect(result.organizationId).toBe(organizationId);
      expect(JSON.stringify(result.data)).not
        .toContain("sensitive@example.invalid");
    });
    it("exports a neutral source projection without modifying CyberScore", async () => {
      const result = await call(admin, "NEUTRAL_BUNDLE", {
        snapshotId,
      });
      const payload = result.data as {
        coverage: { canonicalCyberScoreChanged: boolean };
        findings: unknown[];
      };
      expect(payload.coverage.canonicalCyberScoreChanged).toBe(false);
      expect(payload.findings.length).toBeGreaterThan(0);
      const csv = await call(admin, "NEUTRAL_CSV", {
        snapshotId,
      });
      expect(JSON.stringify(csv.data))
        .not.toContain("sensitive@example.invalid");
      expect(csv.boundaries.externalGoogleRequests).toBe(0);
    });
    it("reports retention candidates without claiming backup erasure", async () => {
      const result = await call(admin, "RETENTION_PREVIEW", {
        limit: 10,
      });
      const plan = result.data as {
        backupErasureProven: boolean;
        databaseRowsDeleted: number;
      };
      expect(plan.backupErasureProven).toBe(false);
      expect(plan.databaseRowsDeleted).toBe(0);
    });
    it("blocks stale CAS and does not create duplicate audit events", async () => {
      await expect(call(admin, "MUTATE_LAB", {
        connectionId, expectedRevision: 0,
        type: "REVOKE", at: "2026-11-12T10:05:00.000Z",
        reason: "Stale revision must not revoke.",
        previousEventDigest: headDigest,
      })).rejects.toMatchObject({ code: "CONFLICT" });
      const count = await db.googleLabEvent.count({
        where: { organizationId, connectionId },
      });
      expect(count).toBe(revision);
    });
  },
);
