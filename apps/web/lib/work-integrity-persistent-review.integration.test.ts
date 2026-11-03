import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  createPersistentReview, applyPersistentReviewCommand,
  getPersistentReview, listPersistentReviews,
  listPersistentReviewEvents, type ReviewScope,
} from "./work-integrity-persistent-review";
import { inspectPersistedReviewLedger } from "./work-integrity-persistent-review-ledger";
import {
  registerPersistentReviewBatch,
  loadPersistentReviewDashboard,
} from "./work-integrity-persistent-review-operations";

/**
 * This suite executes against the migrated PostgreSQL service in CI.
 * No database means no integration assertions, not a simulated success.
 */
const databaseAvailable = Boolean(process.env.DATABASE_URL);
describe.skipIf(!databaseAvailable)(
  "persistent integrity review PostgreSQL integration", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const organizationId = "review-int-org-" + suffix;
    const otherOrganizationId = "review-other-org-" + suffix;
    const userId = "review-int-user-" + suffix;
    const otherUserId = "review-other-user-" + suffix;
    const captureId = "review-int-capture-" + suffix;
    const otherCaptureId = "review-other-capture-" + suffix;
    const scope: ReviewScope = {
      organizationId, userId, role: "ADMIN",
    };
    const otherScope: ReviewScope = {
      organizationId: otherOrganizationId,
      userId: otherUserId, role: "ADMIN",
    };
    const auditor: ReviewScope = {
      ...scope, role: "AUDITOR",
    };
    let createdTaskId = "";
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          {
            id: userId, name: "Review integration actor",
            email: "review-" + suffix + "@example.invalid",
          },
          {
            id: otherUserId, name: "Other review actor",
            email: "other-review-" + suffix + "@example.invalid",
          },
        ],
      });
      await db.organization.createMany({
        data: [
          {
            id: organizationId,
            slug: "review-integration-" + suffix,
            name: "Review integration test",
          },
          {
            id: otherOrganizationId,
            slug: "other-review-integration-" + suffix,
            name: "Other review integration test",
          },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId, userId, role: "ADMIN" },
          {
            organizationId: otherOrganizationId,
            userId: otherUserId, role: "ADMIN",
          },
        ],
      });
      await db.integrityCaseCapture.createMany({
        data: [
          {
            id: captureId, organizationId,
            source: "integration-test", capturedAt: new Date(),
            complete: true, caseCount: 1,
            digest: "a".repeat(64), payload: { cases: [] },
            createdById: userId,
          },
          {
            id: otherCaptureId,
            organizationId: otherOrganizationId,
            source: "integration-test", capturedAt: new Date(),
            complete: true, caseCount: 1,
            digest: "b".repeat(64), payload: { cases: [] },
            createdById: otherUserId,
          },
        ],
      });
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: {
          id: { in: [organizationId, otherOrganizationId] },
        },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, otherUserId] } },
      });
    });
    it("persists creation and audit in the same transaction", async () => {
      const task = await createPersistentReview(scope, {
        captureId, externalTaskId: "test-case-one",
        title: "Inspect the security evidence",
        severity: "ERROR", required: true,
      });
      createdTaskId = task.id;
      expect(task.revision).toBe(1);
      expect(task.disposition).toBe("OPEN");
      const audit = await db.auditEvent.findMany({
        where: {
          organizationId, resourceId: task.id,
          action: "integrity.review.created",
        },
      });
      expect(audit).toHaveLength(1);
      expect(audit[0]?.actorUserId).toBe(userId);
    });
    it("enforces unique review task identities", async () => {
      await expect(createPersistentReview(scope, {
        captureId, externalTaskId: "test-case-one",
        title: "Duplicate task", severity: "ERROR",
      })).rejects.toMatchObject({ code: "CONFLICT" });
      expect(await db.integrityReviewTask.count({
        where: { organizationId, externalTaskId: "test-case-one" },
      })).toBe(1);
    });
    it("prevents cross-tenant read and mutation", async () => {
      await expect(getPersistentReview(otherScope,
        createdTaskId)).rejects.toMatchObject({ code: "MISSING" });
      await expect(applyPersistentReviewCommand(otherScope, {
        taskId: createdTaskId,
        action: "ACKNOWLEDGE",
        expectedRevision: 1,
        idempotencyKey: "other-tenant-attempt-001",
      })).rejects.toMatchObject({ code: "MISSING" });
      const otherList = await listPersistentReviews(otherScope, {});
      expect(otherList.tasks.some(x =>
        x.id === createdTaskId)).toBe(false);
    });
    it("prevents auditors from changing state", async () => {
      await expect(applyPersistentReviewCommand(auditor, {
        taskId: createdTaskId, action: "ACKNOWLEDGE",
        expectedRevision: 1,
        idempotencyKey: "auditor-command-0001",
      })).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
    it("atomically writes state, event, command and audit", async () => {
      const result = await applyPersistentReviewCommand(scope, {
        taskId: createdTaskId, action: "ACKNOWLEDGE",
        expectedRevision: 1,
        idempotencyKey: "acknowledge-command-001",
      });
      expect(result.replayed).toBe(false);
      expect(result.result).toMatchObject({
        taskId: createdTaskId, revision: 2,
        disposition: "ACKNOWLEDGED",
      });
      const task = await getPersistentReview(scope, createdTaskId);
      expect(task.ownerUserId).toBe(userId);
      const events = await listPersistentReviewEvents(scope, {
        taskId: createdTaskId,
      });
      expect(events.total).toBe(1);
      expect(events.events[0]?.revisionAfter).toBe(2);
      const commands = await db.integrityReviewCommand.findMany({
        where: { organizationId, taskId: createdTaskId },
      });
      expect(commands).toHaveLength(1);
      const audits = await db.auditEvent.findMany({
        where: {
          organizationId, resourceId: createdTaskId,
          action: "integrity.review.acknowledge",
        },
      });
      expect(audits).toHaveLength(1);
    });
    it("replays identical idempotency keys without new events", async () => {
      const payload = {
        taskId: createdTaskId, action: "ACKNOWLEDGE",
        expectedRevision: 1,
        idempotencyKey: "acknowledge-command-001",
      };
      const replay = await applyPersistentReviewCommand(scope, payload);
      expect(replay.replayed).toBe(true);
      expect(await db.integrityReviewEvent.count({
        where: { organizationId, taskId: createdTaskId },
      })).toBe(1);
      await expect(applyPersistentReviewCommand(scope, {
        ...payload, reason: "Changed content",
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("rejects stale optimistic revisions", async () => {
      await expect(applyPersistentReviewCommand(scope, {
        taskId: createdTaskId, action: "START_REVIEW",
        expectedRevision: 1,
        idempotencyKey: "stale-revision-0001",
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("does not allow fabricated resolution evidence", async () => {
      await applyPersistentReviewCommand(scope, {
        taskId: createdTaskId, action: "START_REVIEW",
        expectedRevision: 2,
        idempotencyKey: "start-review-0001",
      });
      await expect(applyPersistentReviewCommand(scope, {
        taskId: createdTaskId, action: "RESOLVE",
        expectedRevision: 3,
        idempotencyKey: "resolve-fake-evidence-001",
        reason: "Attempted fake evidence",
        evidenceRefs: ["fabricated-evidence-123"],
      })).rejects.toMatchObject({ code: "INVALID" });
      expect((await getPersistentReview(scope,
        createdTaskId)).revision).toBe(3);
    });
    it("requires evidence from the same tenant", async () => {
      const otherEvidence = await db.securityEvidence.create({
        data: {
          organizationId: otherOrganizationId,
          source: "integration-test",
          domain: "other.invalid", controlId: "test-review",
          state: "OBSERVED", scope: "organization",
        },
      });
      await expect(applyPersistentReviewCommand(scope, {
        taskId: createdTaskId, action: "RESOLVE",
        expectedRevision: 3,
        idempotencyKey: "resolve-other-tenant-001",
        reason: "Attempted cross-tenant evidence",
        evidenceRefs: [otherEvidence.id],
      })).rejects.toMatchObject({ code: "INVALID" });
    });
    it("resolves only with registered tenant evidence", async () => {
      const evidence = await db.securityEvidence.create({
        data: {
          organizationId,
          source: "integration-test", domain: "own.invalid",
          controlId: "test-review", state: "OBSERVED",
          scope: "organization",
        },
      });
      const result = await applyPersistentReviewCommand(scope, {
        taskId: createdTaskId, action: "RESOLVE",
        expectedRevision: 3,
        idempotencyKey: "resolve-with-evidence-001",
        reason: "Evidence reviewed by administrator",
        evidenceRefs: [evidence.id],
      });
      expect(result.result).toMatchObject({
        revision: 4, disposition: "RESOLVED",
      });
      const task = await getPersistentReview(scope, createdTaskId);
      expect(task.resolutionRefs).toEqual([evidence.id]);
      expect(task.completedAt).not.toBeNull();
    });
    it("replays the actual PostgreSQL ledger with command and audit reconciliation", async () => {
      const ledger = await inspectPersistedReviewLedger(scope, createdTaskId);
      expect(ledger.consistent).toBe(true);
      expect(ledger.eventCount).toBe(3);
      expect(ledger.commandCount).toBe(3);
      expect(ledger.auditCount).toBe(3);
      expect(ledger.expectedRevision).toBe(4);
      expect(ledger.expectedDisposition).toBe("RESOLVED");
    });
    it("detects persisted audit corruption and recovers after repair", async () => {
      const audit = await db.auditEvent.findFirstOrThrow({
        where: {
          organizationId, resourceId: createdTaskId,
          action: "integrity.review.resolve",
        },
      });
      const original = audit.metadata;
      try {
        await db.auditEvent.update({
          where: { id: audit.id },
          data: {
            metadata: {
              eventId: "corrupted-event-id",
              revisionBefore: 3,
              revisionAfter: 4,
            },
          },
        });
        const damaged = await inspectPersistedReviewLedger(
          scope, createdTaskId);
        expect(damaged.consistent).toBe(false);
        expect(damaged.findings.some(x =>
          x.code === "AUDIT_MISSING")).toBe(true);
      } finally {
        await db.auditEvent.update({
          where: { id: audit.id },
          data: { metadata: original ?? {} },
        });
      }
      expect((await inspectPersistedReviewLedger(
        scope, createdTaskId)).consistent).toBe(true);
    });
    it("does not reveal a foreign organization's ledger", async () => {
      await expect(inspectPersistedReviewLedger(
        otherScope, createdTaskId)).rejects.toMatchObject({
        code: "MISSING",
      });
    });
    it("registers batches without duplicating existing tasks", async () => {
      const batch = await registerPersistentReviewBatch(scope, {
        captureId, rejectExisting: false,
        tasks: [
          {
            externalTaskId: "test-case-one",
            title: "Existing task", severity: "ERROR",
          },
          {
            externalTaskId: "test-case-two",
            title: "Second task", severity: "WARNING",
          },
        ],
      });
      expect(batch).toMatchObject({
        submitted: 2, created: 1, skippedExisting: 1,
      });
      const dashboard = await loadPersistentReviewDashboard(scope, {
        captureId,
      });
      expect(dashboard.totals.tasks).toBe(2);
      expect(dashboard.totals.resolved).toBe(1);
      expect(dashboard.totals.outstanding).toBe(1);
    });
    it("serializes competing commands at the same revision", async () => {
      const task = await createPersistentReview(scope, {
        captureId, externalTaskId: "competing-review",
        title: "Competing command test", severity: "WARNING",
      });
      const commands = [
        {
          taskId: task.id, action: "ACKNOWLEDGE",
          expectedRevision: 1,
          idempotencyKey: "concurrent-acknowledge-001",
        },
        {
          taskId: task.id, action: "ACKNOWLEDGE",
          expectedRevision: 1,
          idempotencyKey: "concurrent-acknowledge-002",
        },
      ];
      const settled = await Promise.allSettled(
        commands.map(command =>
          applyPersistentReviewCommand(scope, command)));
      const successful = settled.filter(x =>
        x.status === "fulfilled");
      expect(successful).toHaveLength(1);
      expect((await getPersistentReview(scope, task.id)).revision).toBe(2);
      expect(await db.integrityReviewEvent.count({
        where: { organizationId, taskId: task.id },
      })).toBe(1);
      expect(await db.integrityReviewCommand.count({
        where: { organizationId, taskId: task.id },
      })).toBe(1);
    });
    it("coalesces concurrent requests sharing an idempotency key", async () => {
      const task = await createPersistentReview(scope, {
        captureId, externalTaskId: "same-key-review",
        title: "Duplicate command test", severity: "INFO",
      });
      const payload = {
        taskId: task.id, action: "ACKNOWLEDGE",
        expectedRevision: 1,
        idempotencyKey: "concurrent-same-key-001",
      };
      const settled = await Promise.allSettled([
        applyPersistentReviewCommand(scope, payload),
        applyPersistentReviewCommand(scope, payload),
      ]);
      expect(settled.some(x => x.status === "fulfilled")).toBe(true);
      expect(await db.integrityReviewEvent.count({
        where: { organizationId, taskId: task.id },
      })).toBe(1);
      const replay = await applyPersistentReviewCommand(scope, payload);
      expect(replay.replayed).toBe(true);
      expect(await db.integrityReviewCommand.count({
        where: { organizationId, taskId: task.id },
      })).toBe(1);
    });
    it("rejects duplicate IDs in strict batch mode", async () => {
      await expect(registerPersistentReviewBatch(scope, {
        captureId, rejectExisting: true,
        tasks: [{
          externalTaskId: "test-case-one",
          title: "Strict duplicate", severity: "ERROR",
        }],
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
  },
);
