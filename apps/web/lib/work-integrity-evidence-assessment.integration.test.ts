import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "@cyberpilot/database";
import {
  recordEvidenceAssessment, listEvidenceAssessments,
  inspectAssessmentEvidence,
} from "./work-integrity-evidence-assessment";
import { createPersistentReview, type ReviewScope } from "./work-integrity-persistent-review";
import { inspectPersistedReviewLedger } from "./work-integrity-persistent-review-ledger";

/** Executes against the migrated PostgreSQL service; no mock fallback. */
describe.skipIf(!process.env.DATABASE_URL)(
  "phase 3 evidence assessment PostgreSQL integration", () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const organizationId = "assess-org-" + suffix;
    const otherOrganizationId = "assess-other-" + suffix;
    const userId = "assess-user-" + suffix;
    const otherUserId = "assess-other-user-" + suffix;
    const captureId = "assess-capture-" + suffix;
    const scope: ReviewScope = { organizationId, userId, role: "ADMIN" };
    const auditor: ReviewScope = { ...scope, role: "AUDITOR" };
    const other: ReviewScope = {
      organizationId: otherOrganizationId,
      userId: otherUserId, role: "ADMIN",
    };
    let taskId = "";
    let evidenceId = "";
    let otherEvidenceId = "";
    let assessmentId = "";
    const request = () => ({
      taskId, evidenceId, expectedRevision: 0,
      decision: "ACCEPTED",
      rationale: "Reviewed a timestamped observed provider record.",
      idempotencyKey: "assess-first-" + suffix,
    });
    beforeAll(async () => {
      await db.user.createMany({
        data: [
          { id: userId, name: "Assessment user",
            email: "assess-" + suffix + "@example.invalid" },
          { id: otherUserId, name: "Other assessment user",
            email: "assess-other-" + suffix + "@example.invalid" },
        ],
      });
      await db.organization.createMany({
        data: [
          { id: organizationId, name: "Assessment test",
            slug: "assess-" + suffix },
          { id: otherOrganizationId, name: "Other assessment test",
            slug: "assess-other-" + suffix },
        ],
      });
      await db.membership.createMany({
        data: [
          { organizationId, userId, role: "ADMIN" },
          { organizationId: otherOrganizationId, userId: otherUserId, role: "ADMIN" },
        ],
      });
      await db.integrityCaseCapture.create({
        data: {
          id: captureId, organizationId,
          source: "assessment-integration",
          capturedAt: new Date(), complete: true,
          caseCount: 1, digest: "a".repeat(64),
          payload: { cases: [] }, createdById: userId,
        },
      });
      const task = await createPersistentReview(scope, {
        captureId, externalTaskId: "case-one",
        title: "Verify evidence for remediation",
        severity: "ERROR", required: true,
      });
      taskId = task.id;
      const observedAt = new Date("2026-10-01T00:00:00Z");
      const evidence = await db.securityEvidence.create({
        data: {
          organizationId, source: "integration-test",
          domain: "assess.invalid", controlId: "mfa",
          scope: "organization", state: "OBSERVED",
          observedAt, details: { enabled: true },
        },
      });
      evidenceId = evidence.id;
      const otherEvidence = await db.securityEvidence.create({
        data: {
          organizationId: otherOrganizationId,
          source: "integration-test", domain: "other-assess.invalid",
          controlId: "mfa", scope: "organization",
          state: "OBSERVED", observedAt,
        },
      });
      otherEvidenceId = otherEvidence.id;
    });
    afterAll(async () => {
      await db.organization.deleteMany({
        where: { id: { in: [organizationId, otherOrganizationId] } },
      });
      await db.user.deleteMany({
        where: { id: { in: [userId, otherUserId] } },
      });
    });
    it("rejects auditor writes without mutating review", async () => {
      await expect(recordEvidenceAssessment(auditor, request()))
        .rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(await db.integrityEvidenceAssessment.count({
        where: { organizationId },
      })).toBe(0);
    });
    it("rejects evidence from another organization", async () => {
      await expect(recordEvidenceAssessment(scope, {
        ...request(), evidenceId: otherEvidenceId,
      })).rejects.toMatchObject({ code: "MISSING" });
    });
    it("rejects task access from another organization", async () => {
      await expect(recordEvidenceAssessment(other, request()))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("persists the assessment, audit and separate assessment revision", async () => {
      const saved = await recordEvidenceAssessment(scope, request());
      expect(saved.replayed).toBe(false);
      expect(saved.assessment).toMatchObject({
        organizationId, taskId, evidenceId,
        decision: "ACCEPTED", revision: 1,
      });
      assessmentId = saved.assessment.id;
      const task = await db.integrityReviewTask.findFirstOrThrow({
        where: { id: taskId, organizationId },
      });
      expect(task.assessmentRevision).toBe(1);
      expect(task.revision).toBe(1);
      expect(task.disposition).toBe("OPEN");
      const audit = await db.auditEvent.findMany({
        where: {
          organizationId, resourceId: assessmentId,
          action: "integrity.evidence.assessed",
        },
      });
      expect(audit).toHaveLength(1);
      expect(audit[0]?.actorUserId).toBe(userId);
    });
    it("replays idempotent requests without a second audit", async () => {
      const replay = await recordEvidenceAssessment(scope, request());
      expect(replay.replayed).toBe(true);
      expect(replay.assessment.id).toBe(assessmentId);
      expect(await db.integrityEvidenceAssessment.count({
        where: { organizationId, taskId },
      })).toBe(1);
      await expect(recordEvidenceAssessment(scope, {
        ...request(), rationale: "Different rationale for same key.",
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("rejects stale assessment sequence", async () => {
      await expect(recordEvidenceAssessment(scope, {
        ...request(), idempotencyKey: "stale-" + suffix,
      })).rejects.toMatchObject({ code: "CONFLICT" });
    });
    it("does not confuse human assessment with review resolution", async () => {
      const ledger = await inspectPersistedReviewLedger(scope, taskId);
      expect(ledger.consistent).toBe(true);
      expect(ledger.expectedRevision).toBe(1);
      const task = await db.integrityReviewTask.findFirstOrThrow({
        where: { id: taskId },
      });
      expect(task.disposition).toBe("OPEN");
    });
    it("lists assessments only for the scoped organization", async () => {
      const list = await listEvidenceAssessments(scope, { taskId });
      expect(list.total).toBe(1);
      expect(list.assessments[0]?.id).toBe(assessmentId);
      await expect(listEvidenceAssessments(other, { taskId }))
        .rejects.toMatchObject({ code: "MISSING" });
      const readOnly = await listEvidenceAssessments(auditor, { taskId });
      expect(readOnly.total).toBe(1);
    });
    it("detects a changed observation without rewriting historical assessment", async () => {
      const before = await inspectAssessmentEvidence(scope, assessmentId);
      expect(before.consistent).toBe(true);
      expect(before.observationUnchanged).toBe(true);
      await db.securityEvidence.update({
        where: { id: evidenceId },
        data: { state: "ERROR" },
      });
      const after = await inspectAssessmentEvidence(scope, assessmentId);
      expect(after.observationUnchanged).toBe(false);
      expect(after.consistent).toBe(false);
      expect(after.auditMatches).toBe(true);
      await expect(inspectAssessmentEvidence(other, assessmentId))
        .rejects.toMatchObject({ code: "MISSING" });
    });
    it("prevents accepting non-observed evidence", async () => {
      await expect(recordEvidenceAssessment(scope, {
        ...request(), expectedRevision: 1,
        idempotencyKey: "non-observed-" + suffix,
      })).rejects.toMatchObject({ code: "CONFLICT" });
      const saved = await recordEvidenceAssessment(scope, {
        ...request(), expectedRevision: 1,
        decision: "INCONCLUSIVE",
        rationale: "Observation changed; independent verification required.",
        idempotencyKey: "inconclusive-" + suffix,
      });
      expect(saved.assessment.decision).toBe("INCONCLUSIVE");
      expect(saved.assessment.revision).toBe(2);
    });
    it("does not double-write under concurrent identical keys", async () => {
      const payload = {
        ...request(), expectedRevision: 2,
        decision: "REJECTED",
        rationale: "Observed record is now in an error state.",
        idempotencyKey: "concurrent-" + suffix,
      };
      const outcomes = await Promise.allSettled([
        recordEvidenceAssessment(scope, payload),
        recordEvidenceAssessment(scope, payload),
      ]);
      expect(outcomes.some(x => x.status === "fulfilled")).toBe(true);
      expect(await db.integrityEvidenceAssessment.count({
        where: { organizationId, idempotencyKey: payload.idempotencyKey },
      })).toBe(1);
    });
  },
);
