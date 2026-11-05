import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  listInbox, publishNotification, updateInboxNotification,
} from "./work-integrity-notifications";
import {
  openEscalation, transitionEscalation, listEscalations,
} from "./work-integrity-escalations";
import { dispatchCaptureEscalations } from "./work-integrity-escalation-dispatch";
import type { ReviewScope } from "./work-integrity-persistent-review";

describe.skipIf(!process.env.DATABASE_URL)(
  "phase 3C PostgreSQL notification and escalation isolation", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const orgId = "c-org-" + suffix;
    const otherOrgId = "c-other-org-" + suffix;
    const userId = "c-user-" + suffix;
    const otherUserId = "c-other-user-" + suffix;
    const captureId = "c-capture-" + suffix;
    const taskId = "c-task-" + suffix;
    const scope: ReviewScope = {
      organizationId: orgId, userId, role: "ADMIN",
    };
    const other: ReviewScope = {
      organizationId: otherOrgId, userId: otherUserId, role: "ADMIN",
    };
    const now = new Date("2026-11-03T15:00:00Z");
    let notificationId = "";
    let escalationId = "";
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: userId, name: "Inbox admin",
            email: "inbox-" + suffix + "@example.invalid" },
          { id: otherUserId, name: "Other inbox admin",
            email: "other-inbox-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: orgId, name: "Inbox organization",
            slug: "inbox-" + suffix },
          { id: otherOrgId, name: "Other inbox organization",
            slug: "other-inbox-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: orgId, userId, role: "ADMIN" },
          { organizationId: otherOrgId, userId: otherUserId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId: orgId,
          source: "phase3c-integration",
          capturedAt: new Date("2026-11-02T00:00:00Z"),
          complete: true, caseCount: 1,
          digest: "a".repeat(64),
          payload: { cases: [] }, createdById: userId,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: taskId, organizationId: orgId, captureId,
          externalTaskId: "overdue-review",
          title: "Check overdue integrity review",
          severity: "ERROR", required: true,
          ownerUserId: userId,
          createdAt: new Date("2026-11-02T00:00:00Z"),
        },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [orgId, otherOrgId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, otherUserId] } },
      });
    });
    it("publishes an in-app notification and replays its key", async () => {
      const payload = {
        taskId, recipientUserId: userId,
        kind: "REVIEW_ASSIGNED",
        dedupeKey: "assignment-" + suffix,
        title: "Integrity review assigned",
        message: "An integrity review has been assigned to you.",
      };
      const first = await publishNotification(scope, payload);
      expect(first.replayed).toBe(false);
      notificationId = first.notification.id;
      const replay = await publishNotification(scope, payload);
      expect(replay.replayed).toBe(true);
      expect(replay.notification.id).toBe(notificationId);
      await expect(publishNotification(scope, {
        ...payload, title: "Different notification",
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("isolates the inbox to the recipient and organization", async () => {
      const inbox = await listInbox(scope, { unreadOnly: true });
      expect(inbox.notifications.some(x => x.id === notificationId)).toBe(true);
      const isolated = await listInbox(other, {});
      expect(isolated.total).toBe(0);
      await expect(publishNotification(other, {
        taskId, recipientUserId: otherUserId,
        kind: "REVIEW_ASSIGNED", dedupeKey: "cross-org-" + suffix,
        title: "Invalid cross-tenant notification",
        message: "This should never be persisted.",
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("updates recipient state with optimistic concurrency", async () => {
      const read = await updateInboxNotification(scope, {
        notificationId, action: "READ", expectedRevision: 1,
      });
      expect(read.notification.readAt).not.toBeNull();
      expect(read.notification.revision).toBe(2);
      await expect(updateInboxNotification(scope, {
        notificationId, action: "DISMISS", expectedRevision: 1,
      })).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(updateInboxNotification(other, {
        notificationId, action: "DISMISS", expectedRevision: 2,
      })).rejects.toMatchObject({ code: "MISSING" });
      const dismissed = await updateInboxNotification(scope, {
        notificationId, action: "DISMISS", expectedRevision: 2,
      });
      expect(dismissed.notification.dismissedAt).not.toBeNull();
      const inbox = await listInbox(scope, {});
      expect(inbox.notifications.some(x => x.id === notificationId)).toBe(false);
    });
    it("opens a deduplicated escalation and audits the lifecycle", async () => {
      const first = await openEscalation(scope, { taskId }, now);
      escalationId = first.escalation.id;
      expect(first.escalation.level).toBe(2);
      const replay = await openEscalation(scope, { taskId }, now);
      expect(replay.replayed).toBe(true);
      expect(replay.escalation.id).toBe(escalationId);
      const ack = await transitionEscalation(scope, {
        escalationId, action: "ACKNOWLEDGE",
        expectedRevision: 1,
        reason: "The administrator has accepted the review escalation.",
      }, now);
      expect(ack.escalation.state).toBe("ACKNOWLEDGED");
      await expect(transitionEscalation(scope, {
        escalationId, action: "RESOLVE",
        expectedRevision: 1,
        reason: "This revision has already been superseded.",
      }, now)).rejects.toMatchObject({ code: "CONFLICT" });
      const resolved = await transitionEscalation(scope, {
        escalationId, action: "RESOLVE",
        expectedRevision: 2,
        reason: "The overdue review was assessed by the administrator.",
      }, now);
      expect(resolved.escalation.state).toBe("RESOLVED");
      expect((await listEscalations(scope, { taskId })).total).toBe(1);
      expect((await listEscalations(other, {})).total).toBe(0);
    });
    it("previews dispatch without persistence and routes only to tenant members", async () => {
      const preview = await dispatchCaptureEscalations(scope, {
        captureId, dryRun: true,
      }, now);
      expect(preview.rows).toHaveLength(1);
      expect(preview.rows[0]?.recipients).toEqual([userId]);
      expect(preview.rows[0]?.escalationId).toBeNull();
    });
    it("dispatches exactly one inbox item per escalation and recipient", async () => {
      const first = await dispatchCaptureEscalations(scope, {
        captureId, dryRun: false,
      }, now);
      expect(first.rows[0]?.escalationId).toBe(escalationId);
      expect(first.rows[0]?.notificationIds).toHaveLength(1);
      const replay = await dispatchCaptureEscalations(scope, {
        captureId, dryRun: false,
      }, now);
      expect(replay.rows[0]?.replayed).toBe(true);
      expect(replay.rows[0]?.notificationIds)
        .toEqual(first.rows[0]?.notificationIds);
      const inbox = await listInbox(scope, { kind: "REVIEW_ESCALATED" });
      expect(inbox.total).toBe(1);
    });
    it("does not change review disposition or security score", async () => {
      const task = await db.integrityReviewTask.findFirstOrThrow({
        where: { id: taskId, organizationId: orgId },
      });
      expect(task.disposition).toBe("OPEN");
      expect(task.revision).toBe(1);
      const events = await db.auditEvent.findMany({
        where: {
          organizationId: orgId,
          resourceType: { in: ["IntegrityNotification", "IntegrityEscalation"] },
        },
      });
      expect(events.length).toBeGreaterThanOrEqual(4);
    });
  },
);
