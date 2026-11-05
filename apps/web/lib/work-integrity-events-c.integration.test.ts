import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { reconcileIntegrityEvents } from "./work-integrity-event-notifications";
import { inspectIntegrityNotifications } from "./work-integrity-notification-inspection";
import type { ReviewScope } from "./work-integrity-persistent-review";

describe.skipIf(!process.env.DATABASE_URL)(
  "phase 3C PostgreSQL event notifications and provenance", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const orgId = "events-org-" + suffix;
    const otherOrgId = "events-other-" + suffix;
    const adminId = "events-admin-" + suffix;
    const outsiderId = "events-outsider-" + suffix;
    const captureId = "events-capture-" + suffix;
    const taskId = "events-task-" + suffix;
    const scope: ReviewScope = {
      organizationId: orgId, userId: adminId, role: "ADMIN",
    };
    const other: ReviewScope = {
      organizationId: otherOrgId, userId: outsiderId, role: "ADMIN",
    };
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: adminId, name: "Event admin",
            email: "events-admin-" + suffix + "@example.invalid" },
          { id: outsiderId, name: "Event outsider",
            email: "events-outsider-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: orgId, name: "Event organization",
            slug: "events-" + suffix },
          { id: otherOrgId, name: "Other event organization",
            slug: "events-other-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: orgId, userId: adminId, role: "ADMIN" },
          { organizationId: otherOrgId, userId: outsiderId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId: orgId,
          source: "event-reconciliation-integration",
          capturedAt: new Date("2026-11-02T00:00:00.000Z"),
          complete: true, caseCount: 1,
          digest: "c".repeat(64),
          payload: { cases: [] },
          createdById: adminId,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: taskId, organizationId: orgId,
          captureId, externalTaskId: "event-resolution",
          title: "Human evidence resolution",
          severity: "WARNING", required: true,
          disposition: "RESOLVED", revision: 2,
          ownerUserId: adminId,
          completedAt: new Date("2026-11-03T11:00:00.000Z"),
        },
      });
      await db.integrityReviewEvent.create({
        data: {
          organizationId: orgId, taskId, actorUserId: adminId,
          action: "RESOLVE",
          before: "IN_REVIEW", after: "RESOLVED",
          revisionBefore: 1, revisionAfter: 2,
          reason: "The human review is complete and documented.",
        },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [orgId, otherOrgId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, outsiderId] } },
      });
    });
    it("previews source event without creating inbox records", async () => {
      const preview = await reconcileIntegrityEvents(scope, {
        captureId,
      });
      expect(preview.dryRun).toBe(true);
      expect(preview.reviewEventsScanned).toBe(1);
      expect(preview.plannedNotifications).toBe(1);
      expect(preview.created).toBe(0);
      expect(await db.integrityNotification.count({
        where: { organizationId: orgId },
      })).toBe(0);
    });
    it("persists exactly one audited in-app event notification", async () => {
      const result = await reconcileIntegrityEvents(scope, {
        captureId, dryRun: false,
      });
      expect(result.created).toBe(1);
      expect(result.replayed).toBe(0);
      const notifications = await db.integrityNotification.findMany({
        where: { organizationId: orgId },
      });
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({
        taskId, recipientUserId: adminId,
        kind: "REVIEW_RESOLVED",
      });
      const audits = await db.auditEvent.findMany({
        where: {
          organizationId: orgId,
          resourceType: "IntegrityNotification",
        },
      });
      expect(audits).toHaveLength(1);
      expect(audits[0]?.action)
        .toBe("integrity.notification.event_reconciled");
    });
    it("replays without duplicating notification or audit", async () => {
      const replay = await reconcileIntegrityEvents(scope, {
        captureId, dryRun: false,
      });
      expect(replay.replayed).toBe(1);
      expect(replay.created).toBe(0);
      expect(await db.integrityNotification.count({
        where: { organizationId: orgId },
      })).toBe(1);
      expect(await db.auditEvent.count({
        where: {
          organizationId: orgId,
          resourceType: "IntegrityNotification",
        },
      })).toBe(1);
    });
    it("inspects event provenance and detects no source mismatch", async () => {
      const report = await inspectIntegrityNotifications(scope, {});
      expect(report.total).toBe(1);
      expect(report.consistent).toBe(1);
      expect(report.inconsistent).toBe(0);
      expect(report.rows[0]?.source).toBe("REVIEW");
      expect(report.digest).toMatch(/^[0-9a-f]{64}$/);
    });
    it("isolates reconciliation and inspection across tenants", async () => {
      await expect(reconcileIntegrityEvents(other, {
        captureId,
      })).rejects.toMatchObject({ code: "MISSING" });
      const report = await inspectIntegrityNotifications(other, {});
      expect(report.total).toBe(0);
      expect(report.rows).toEqual([]);
    });
    it("does not mutate review disposition or security score", async () => {
      const task = await db.integrityReviewTask.findFirstOrThrow({
        where: { id: taskId, organizationId: orgId },
      });
      expect(task.disposition).toBe("RESOLVED");
      expect(task.revision).toBe(2);
      expect(task.assessmentRevision).toBe(0);
    });
  },
);
