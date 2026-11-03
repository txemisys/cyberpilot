import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { triageReviewBatch, inspectTriageHistory } from "./work-integrity-review-triage";
import { readIntegrityOperationsQueue } from "./work-integrity-operations-queue";
import { readIntegrityOperationsMetrics } from "./work-integrity-operations-metrics";
import type { ReviewScope } from "./work-integrity-persistent-review";

describe.skipIf(!process.env.DATABASE_URL)(
  "phase 3C PostgreSQL triage and operational reports", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const orgId = "triage-org-" + suffix;
    const otherOrgId = "triage-other-" + suffix;
    const adminId = "triage-admin-" + suffix;
    const memberId = "triage-member-" + suffix;
    const outsiderId = "triage-outsider-" + suffix;
    const captureId = "triage-capture-" + suffix;
    const taskId = "triage-task-" + suffix;
    const scope: ReviewScope = {
      organizationId: orgId, userId: adminId, role: "ADMIN",
    };
    const other: ReviewScope = {
      organizationId: otherOrgId, userId: outsiderId, role: "ADMIN",
    };
    const now = new Date("2026-11-03T12:00:00.000Z");
    const note = "The review requires ownership and operational follow-up.";
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: adminId, name: "Triage administrator",
            email: "triage-admin-" + suffix + "@example.invalid" },
          { id: memberId, name: "Triage member",
            email: "triage-member-" + suffix + "@example.invalid" },
          { id: outsiderId, name: "Triage outsider",
            email: "triage-outsider-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: orgId, name: "Triage organization",
            slug: "triage-" + suffix },
          { id: otherOrgId, name: "Triage other organization",
            slug: "triage-other-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: orgId, userId: adminId, role: "ADMIN" },
          { organizationId: orgId, userId: memberId, role: "MEMBER" },
          { organizationId: otherOrgId, userId: outsiderId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId: orgId,
          source: "triage-integration",
          capturedAt: new Date("2026-11-02T00:00:00.000Z"),
          complete: true, caseCount: 1,
          digest: "b".repeat(64), payload: { cases: [] },
          createdById: adminId,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: taskId, organizationId: orgId,
          captureId, externalTaskId: "triage-overdue",
          title: "Overdue provider evidence review",
          severity: "ERROR", required: true,
          createdAt: new Date("2026-11-02T00:00:00.000Z"),
        },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [orgId, otherOrgId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [adminId, memberId, outsiderId] } },
      });
    });
    it("reports overdue unassigned review without inventing provider proof", async () => {
      const report = await readIntegrityOperationsQueue(scope, {
        captureId,
      }, now);
      expect(report.total).toBe(1);
      expect(report.rows[0]).toMatchObject({
        taskId, bucket: "OVERDUE",
        ownerUserId: null,
        evidence: { providerChecks: 0, latestProviderOutcome: null },
      });
      expect(report.rows[0]?.flags).toContain("NO_PROVIDER_CHECK");
      expect((await readIntegrityOperationsQueue(other, {}, now)).total)
        .toBe(0);
    });
    it("previews assignment without modifying task", async () => {
      const preview = await triageReviewBatch(scope, {
        commands: [{
          taskId, action: "ASSIGN", expectedRevision: 1,
          recipientUserId: memberId, note,
          idempotencyKey: "preview-" + suffix,
        }],
      }, now);
      expect(preview.previewed).toBe(1);
      const task = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: taskId },
      });
      expect(task.ownerUserId).toBeNull();
      expect(task.revision).toBe(1);
    });
    it("rejects cross-tenant assignment", async () => {
      const result = await triageReviewBatch(scope, {
        dryRun: false,
        commands: [{
          taskId, action: "ASSIGN", expectedRevision: 1,
          recipientUserId: outsiderId, note,
          idempotencyKey: "cross-tenant-" + suffix,
        }],
      }, now);
      expect(result.failed).toBe(1);
      expect(result.results[0]?.errorCode).toBe("MISSING");
    });
    it("commits an assignment and in-app message with audit trail", async () => {
      const command = {
        taskId, action: "ASSIGN", expectedRevision: 1,
        recipientUserId: memberId, note,
        idempotencyKey: "assignment-" + suffix,
      };
      const first = await triageReviewBatch(scope, {
        dryRun: false, commands: [command],
      }, now);
      expect(first.applied).toBe(1);
      expect(first.results[0]?.revisionAfter).toBe(1);
      expect(first.results[0]?.notificationIds).toHaveLength(1);
      const task = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: taskId },
      });
      expect(task.ownerUserId).toBe(memberId);
      expect(task.revision).toBe(1);
      const replay = await triageReviewBatch(scope, {
        dryRun: false, commands: [command],
      }, now);
      expect(replay.replayed).toBe(1);
      const changed = await triageReviewBatch(scope, {
        dryRun: false,
        commands: [{ ...command, note: "A different assignment reason was provided." }],
      }, now);
      expect(changed.failed).toBe(1);
      expect(changed.results[0]?.errorCode).toBe("CONFLICT");
    });
    it("creates a manual owner reminder without changing review disposition", async () => {
      const result = await triageReviewBatch(scope, {
        dryRun: false,
        commands: [{
          taskId, action: "NOTIFY_OWNER", expectedRevision: 1,
          note: "Please review the overdue evidence and update the case.",
          idempotencyKey: "notify-owner-" + suffix,
        }],
      }, now);
      expect(result.applied).toBe(1);
      const notifications = await db.integrityNotification.findMany({
        where: { organizationId: orgId, taskId },
      });
      expect(notifications).toHaveLength(2);
      expect(notifications.every(x => x.recipientUserId === memberId))
        .toBe(true);
      const task = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: taskId },
      });
      expect(task.disposition).toBe("OPEN");
    });
    it("restricts triage to administrators and tenant scope", async () => {
      const member: ReviewScope = {
        organizationId: orgId, userId: memberId, role: "MEMBER",
      };
      await expect(triageReviewBatch(member, {
        dryRun: false,
        commands: [{
          taskId, action: "UNASSIGN", expectedRevision: 1,
          note, idempotencyKey: "member-denied-" + suffix,
        }],
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
      const result = await triageReviewBatch(other, {
        dryRun: false,
        commands: [{
          taskId, action: "UNASSIGN", expectedRevision: 1,
          note, idempotencyKey: "outsider-denied-" + suffix,
        }],
      }, now);
      expect(result.failed).toBe(1);
      expect(result.results[0]?.errorCode).toBe("MISSING");
    });
    it("exposes audit history only within the tenant", async () => {
      const history = await inspectTriageHistory(scope, { taskId });
      expect(history.total).toBe(2);
      expect(history.events.every(x => x.actorUserId === adminId)).toBe(true);
      await expect(inspectTriageHistory(other, {
        taskId,
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("produces bounded metrics without claiming security improvement", async () => {
      const metrics = await readIntegrityOperationsMetrics(scope, {
        captureId,
        from: "2026-11-01T00:00:00.000Z",
        to: "2026-11-04T00:00:00.000Z",
      }, now);
      expect(metrics.summary.tasksCreated).toBe(1);
      expect(metrics.summary.providerPassed).toBe(0);
      expect(metrics.digest).toMatch(/^[0-9a-f]{64}$/);
      await expect(readIntegrityOperationsMetrics(other, {
        captureId,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
    });
  },
);
