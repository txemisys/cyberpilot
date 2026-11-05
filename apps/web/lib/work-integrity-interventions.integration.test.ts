import { randomUUID } from "node:crypto";
import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import { executeIntegrityInterventions } from "./work-integrity-interventions";
import { readInterventionHistory } from "./work-integrity-intervention-history";
import type { ReviewScope } from "./work-integrity-persistent-review";

describe.skipIf(!process.env.DATABASE_URL)(
  "phase 3C controlled interventions PostgreSQL integration", () => {
    const id = randomUUID().replaceAll("-", "").slice(0, 16);
    const org = "intervention-org-" + id;
    const other = "intervention-other-" + id;
    const admin = "intervention-admin-" + id;
    const member = "intervention-member-" + id;
    const outsider = "intervention-outsider-" + id;
    const capture = "intervention-capture-" + id;
    const task = "intervention-task-" + id;
    const scope: ReviewScope = {
      organizationId: org, userId: admin, role: "ADMIN",
    };
    const foreign: ReviewScope = {
      organizationId: other, userId: outsider, role: "ADMIN",
    };
    const now = new Date("2026-11-05T10:00:00.000Z");
    const reason = "Please investigate and follow up on this overdue case.";
    const assignment = {
      taskId: task, kind: "ASSIGN_OWNER",
      expectedRevision: 1, expectedOwnerUserId: null,
      assigneeUserId: member, note: reason,
      idempotencyKey: "intervention-assign-" + id,
    };
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: admin, name: "Intervention admin",
            email: "intervention-admin-" + id + "@example.invalid" },
          { id: member, name: "Intervention member",
            email: "intervention-member-" + id + "@example.invalid" },
          { id: outsider, name: "Intervention outsider",
            email: "intervention-outsider-" + id + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: org, name: "Intervention organization",
            slug: "intervention-" + id },
          { id: other, name: "Intervention other",
            slug: "intervention-other-" + id },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId: org, userId: admin, role: "ADMIN" },
          { organizationId: org, userId: member, role: "MEMBER" },
          { organizationId: other, userId: outsider, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: capture, organizationId: org,
          source: "intervention-integration",
          capturedAt: new Date("2026-11-02T00:00:00.000Z"),
          complete: true, caseCount: 1,
          digest: "a".repeat(64), payload: { cases: [] },
          createdById: admin,
        },
      });
      await db.integrityReviewTask.create({
        data: {
          id: task, organizationId: org,
          captureId: capture, externalTaskId: "intervention-review",
          title: "Explicit intervention approval case",
          severity: "ERROR", required: true,
          createdAt: new Date("2026-11-02T00:00:00.000Z"),
        },
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [org, other] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [admin, member, outsider] } },
      });
    });
    it("denies foreign tenants and ordinary members", async () => {
      await expect(executeIntegrityInterventions(foreign, {
        captureId: capture, commands: [assignment],
      }, now)).rejects.toMatchObject({ code: "MISSING" });
      await expect(executeIntegrityInterventions({
        organizationId: org, userId: member, role: "MEMBER",
      }, {
        captureId: capture, commands: [assignment], dryRun: false,
      }, now)).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("previews assignment without any persistent writes", async () => {
      const preview = await executeIntegrityInterventions(scope, {
        captureId: capture, commands: [assignment],
      }, now);
      expect(preview.previewed).toBe(1);
      expect(preview.applied).toBe(0);
      const persisted = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: task },
      });
      expect(persisted.ownerUserId).toBeNull();
      expect(await db.integrityNotification.count({
        where: { organizationId: org },
      })).toBe(0);
    });
    it("applies an audited assignment once and safely replays it", async () => {
      const first = await executeIntegrityInterventions(scope, {
        captureId: capture, commands: [assignment], dryRun: false,
      }, now);
      expect(first.applied).toBe(1);
      const replay = await executeIntegrityInterventions(scope, {
        captureId: capture, commands: [assignment], dryRun: false,
      }, now);
      expect(replay.replayed).toBe(1);
      const persisted = await db.integrityReviewTask.findUniqueOrThrow({
        where: { id: task },
      });
      expect(persisted.ownerUserId).toBe(member);
      expect(persisted.revision).toBe(1);
      expect(await db.integrityNotification.count({
        where: { organizationId: org, taskId: task },
      })).toBe(1);
      expect(await db.auditEvent.count({
        where: {
          organizationId: org, resourceId: task,
          action: "integrity.triage.assign",
        },
      })).toBe(1);
    });
    it("rejects a stale expected owner and a conflicting idempotency payload", async () => {
      const stale = await executeIntegrityInterventions(scope, {
        captureId: capture, dryRun: false,
        commands: [{
          ...assignment, idempotencyKey: "stale-owner-" + id,
        }],
      }, now);
      expect(stale.failed).toBe(1);
      expect(stale.results[0]?.errorCode).toBe("CONFLICT");
      const changed = await executeIntegrityInterventions(scope, {
        captureId: capture, dryRun: false,
        commands: [{
          ...assignment, note: "This different reason should be rejected.",
        }],
      }, now);
      expect(changed.failed).toBe(1);
      expect(changed.results[0]?.errorCode).toBe("CONFLICT");
    });
    it("records an explicit in-app reminder and audit trail", async () => {
      const reminder = await executeIntegrityInterventions(scope, {
        captureId: capture, dryRun: false,
        commands: [{
          taskId: task, kind: "REMIND_OWNER",
          expectedRevision: 1, expectedOwnerUserId: member,
          note: "Please review the evidence and update the case.",
          idempotencyKey: "intervention-remind-" + id,
        }],
      }, now);
      expect(reminder.applied).toBe(1);
      expect(await db.integrityNotification.count({
        where: { organizationId: org, taskId: task },
      })).toBe(2);
    });
    it("reads administrator-only scoped history with pseudonyms", async () => {
      const history = await readInterventionHistory(scope, {
        captureId: capture,
      }, now);
      expect(history.total).toBe(2);
      expect(history.complete).toBe(true);
      expect(history.entries.every(x => x.actorHash !== admin)).toBe(true);
      expect(history.digest).toMatch(/^[a-f0-9]{64}$/);
      await expect(readInterventionHistory(foreign, {
        captureId: capture,
      }, now)).rejects.toMatchObject({ code: "MISSING" });
      await expect(readInterventionHistory({
        organizationId: org, userId: member, role: "MEMBER",
      }, { captureId: capture }, now)).rejects.toMatchObject({
        code: "FORBIDDEN",
      });
    });
  },
);
