import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { readPhase3CAcceptance } from "./work-integrity-phase3c-acceptance";
import type { ReviewScope } from "./work-integrity-persistent-review";

describe.skipIf(!process.env.DATABASE_URL)(
  "phase 3C acceptance PostgreSQL tenant and persistence", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const organizationId = "acceptance-org-" + suffix;
    const foreignId = "acceptance-other-" + suffix;
    const adminId = "acceptance-admin-" + suffix;
    const memberId = "acceptance-member-" + suffix;
    const foreignUserId = "acceptance-outsider-" + suffix;
    const captureId = "acceptance-capture-" + suffix;
    const taskId = "acceptance-task-" + suffix;
    const now = new Date("2026-11-05T12:00:00.000Z");
    const admin: ReviewScope = {
      organizationId, userId: adminId, role: "ADMIN",
    };
    const member: ReviewScope = {
      organizationId, userId: memberId, role: "MEMBER",
    };
    const outsider: ReviewScope = {
      organizationId: foreignId, userId: foreignUserId, role: "ADMIN",
    };
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: adminId, name: "Acceptance administrator",
            email: "acceptance-admin-" + suffix + "@example.invalid" },
          { id: memberId, name: "Acceptance member",
            email: "acceptance-member-" + suffix + "@example.invalid" },
          { id: foreignUserId, name: "Acceptance outsider",
            email: "acceptance-outsider-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: organizationId, name: "Acceptance organization",
            slug: "acceptance-" + suffix },
          { id: foreignId, name: "Other acceptance organization",
            slug: "acceptance-other-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId, userId: adminId, role: "ADMIN" },
          { organizationId, userId: memberId, role: "MEMBER" },
          { organizationId: foreignId, userId: foreignUserId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId,
          source: "acceptance-integration",
          capturedAt: new Date("2026-11-03T00:00:00.000Z"),
          complete: true, caseCount: 1,
          digest: "c".repeat(64), payload: { cases: [] },
          createdById: adminId,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: taskId, captureId, organizationId,
          externalTaskId: "phase3c-acceptance-review",
          title: "Operational acceptance review",
          severity: "WARNING", required: true,
          createdAt: new Date("2026-11-03T12:00:00.000Z"),
        },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, foreignId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, foreignUserId] } },
      });
    });
    it("refuses unauthenticated roles and foreign capture access", async () => {
      await expect(readPhase3CAcceptance(member, {
        captureId,
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(readPhase3CAcceptance(outsider, {
        captureId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
    it("reports the baseline without falsely inventing revision events", async () => {
      const report = await readPhase3CAcceptance(admin, {
        captureId,
      }, now);
      expect(report.complete).toBe(true);
      expect(report.totalTasks).toBe(1);
      expect(report.summary.tasks).toBe(1);
      expect(report.tasks[0]?.revision).toBe(1);
      expect(report.summary.byCode.NO_REVIEW_EVENTS).toBeUndefined();
      expect(report.tasks[0]?.providerChecks).toBe(0);
      expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
    });
    it("honors page bounds and exposes conservative coverage", async () => {
      const report = await readPhase3CAcceptance(admin, {
        captureId, offset: 1, limit: 1,
      }, now);
      expect(report.complete).toBe(false);
      expect(report.totalTasks).toBe(1);
      expect(report.outcome).toBe("REQUIRES_REVIEW");
      expect(report.tasks).toHaveLength(0);
    });
    it("detects persisted unread notification and expired recipient status", async () => {
      await db.integrityNotification.create({
        data: {
          organizationId, taskId,
          recipientUserId: foreignUserId,
          kind: "REVIEW_OVERDUE",
          dedupeKey: "acceptance-overdue-" + suffix,
          title: "Operational review pending",
          message: "Check review status and provide an update.",
          createdAt: new Date("2026-11-03T12:00:00.000Z"),
        },
      });
      const report = await readPhase3CAcceptance(admin, {
        captureId, maxNotificationAgeHours: 24,
      }, now);
      expect(report.outcome).toBe("REQUIRES_REVIEW");
      expect(report.summary.byCode.NOTIFICATION_UNREAD_AGED).toBe(1);
      expect(report.summary.byCode.NOTIFICATION_RECIPIENT_NOT_MEMBER).toBe(1);
    });
    it("does not change review or notification state during inspection", async () => {
      const before = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: taskId },
      });
      await readPhase3CAcceptance(admin, { captureId }, now);
      const after = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: taskId },
      });
      expect(after.revision).toBe(before.revision);
      expect(after.disposition).toBe(before.disposition);
      expect(after.ownerUserId).toBe(before.ownerUserId);
    });
  },
);
