import { describe, expect, it } from "vitest";
import {
  parseIntegrityReviewEvidenceAssociations,
  reconcileIntegrityReviewEvidence,
  parseIntegrityReviewEvidenceQuery,
  queryIntegrityReviewEvidence,
} from "./work-integrity-remediation-review-evidence";
import {
  parseIntegrityReviewDeadlinePolicy,
  evaluateIntegrityReviewDeadlines,
  parseIntegrityReviewDeadlineQuery,
  queryIntegrityReviewDeadlines,
} from "./work-integrity-remediation-review-deadlines";
import {
  parseIntegrityReviewEscalationPolicy,
  buildIntegrityReviewEscalations,
  parseIntegrityReviewEscalationQuery,
  queryIntegrityReviewEscalations,
} from "./work-integrity-remediation-review-escalations";
import {
  parseIntegrityReviewEvents,
  replayIntegrityReviewEvents,
} from "./work-integrity-remediation-review-event-replay";
import type { IntegrityCapacityReviewQueue } from "./work-integrity-remediation-capacity-review-queue";
const at = "2026-11-03T00:00:00.000Z";
const later = "2026-11-03T02:00:00.000Z";
const queue: IntegrityCapacityReviewQueue = {
  schemaVersion: 1, captureId: "capture", evaluatedAt: at,
  tasks: [{
    taskId: "task", action: "VERIFY_ASSIGNMENT_IMPACT",
    severity: "ERROR", bundleId: "bundle",
    interventionIds: ["intervention"], findingCodes: [],
    reasons: [], priority: 400, position: 1,
    reviewRequired: true, checklist: [],
    affectedCandidateIds: [], blockedBy: [],
    canBeAutoResolved: false,
  }],
  totals: {
    tasks: 1, errors: 1, warnings: 0, info: 0,
    required: 1, affectedCandidates: 0,
    byAction: {}, byBundle: {},
  },
  limitation: "Analytical",
};
const events = parseIntegrityReviewEvents([
  { eventId: "ack", taskId: "task", kind: "ACKNOWLEDGE",
    actorId: "actor", occurredAt: at, expectedVersion: 0 },
  { eventId: "start", taskId: "task", kind: "START_REVIEW",
    actorId: "actor", occurredAt: "2026-11-03T01:00:00.000Z",
    expectedVersion: 1 },
  { eventId: "done", taskId: "task", kind: "RESOLVE",
    actorId: "actor", occurredAt: later, expectedVersion: 2,
    reason: "Reviewed", evidenceRefs: ["ref"] },
]);
const replay = replayIntegrityReviewEvents(queue, events);
const association = {
  associationId: "link", captureId: "capture",
  taskId: "task", reference: "ref",
  recordedAt: at, source: "LINK_AUDIT",
};
describe("scoped review evidence reconciliation", () => {
  it("matches active task evidence without claiming verification", () => {
    const associations = parseIntegrityReviewEvidenceAssociations([
      association,
    ]);
    const report = reconcileIntegrityReviewEvidence(
      queue, replay, events, associations);
    expect(report.references[0]?.status).toBe("ACTIVE");
    expect(report.tasks[0]?.provenanceComplete).toBe(true);
    expect(report.tasks[0]?.independentlyVerified).toBe(false);
  });
  it("rejects withdrawn evidence at review time", () => {
    const associations = parseIntegrityReviewEvidenceAssociations([{
      ...association, withdrawnAt: "2026-11-03T01:30:00.000Z",
    }]);
    const report = reconcileIntegrityReviewEvidence(
      queue, replay, events, associations);
    expect(report.references[0]?.status).toBe("WITHDRAWN");
    expect(report.totals.errors).toBeGreaterThan(0);
  });
  it("detects cross-task and cross-capture references", () => {
    const associations = parseIntegrityReviewEvidenceAssociations([
      { ...association, taskId: "another" },
      { ...association, associationId: "other",
        captureId: "different", taskId: "task" },
    ]);
    const report = reconcileIntegrityReviewEvidence(
      queue, replay, events, associations);
    expect(report.references[0]?.status).toBe("CROSS_CAPTURE");
  });
  it("filters mismatched references", () => {
    const report = reconcileIntegrityReviewEvidence(
      queue, replay, events, []);
    const page = queryIntegrityReviewEvidence(report,
      parseIntegrityReviewEvidenceQuery({ onlyMismatches: true }));
    expect(page.total).toBe(1);
  });
  it("rejects unrecognized evidence association fields", () => {
    expect(() => parseIntegrityReviewEvidenceAssociations([{
      ...association, verified: true,
    }])).toThrow();
  });
});
describe("review deadline evaluation", () => {
  it("computes deadlines and timely completion", () => {
    const policy = parseIntegrityReviewDeadlinePolicy(undefined, later);
    const report = evaluateIntegrityReviewDeadlines(
      queue, replay, events, policy);
    expect(report.totals.completedOnTime).toBe(1);
    expect(report.tasks[0]?.acknowledgmentBreached).toBe(false);
  });
  it("flags overdue outstanding review", () => {
    const policy = parseIntegrityReviewDeadlinePolicy(undefined,
      "2026-11-05T00:00:00.000Z");
    const pending = replayIntegrityReviewEvents(queue, []);
    const report = evaluateIntegrityReviewDeadlines(
      queue, pending, [], policy);
    expect(report.tasks[0]?.resolutionBreached).toBe(true);
    expect(report.tasks[0]?.escalationRequired).toBe(true);
  });
  it("counts business hours only when configured", () => {
    const policy = parseIntegrityReviewDeadlinePolicy({
      useBusinessHours: true, businessDayStartHour: 9,
      businessDayEndHour: 17,
    }, "2026-11-05T12:00:00.000Z");
    const report = evaluateIntegrityReviewDeadlines(
      queue, replayIntegrityReviewEvents(queue, []), [], policy);
    expect(report.tasks[0]?.acknowledgmentDeadline).toContain("T13:00:00");
  });
  it("filters breached deadlines", () => {
    const policy = parseIntegrityReviewDeadlinePolicy(undefined,
      "2026-11-05T00:00:00.000Z");
    const report = evaluateIntegrityReviewDeadlines(
      queue, replayIntegrityReviewEvents(queue, []), [], policy);
    const page = queryIntegrityReviewDeadlines(report,
      parseIntegrityReviewDeadlineQuery({ onlyBreached: true }));
    expect(page.total).toBe(1);
  });
  it("rejects inconsistent deadlines", () => {
    expect(() => parseIntegrityReviewDeadlinePolicy({
      rules: [
        { severity: "ERROR", acknowledgeWithinHours: 30,
          resolveWithinHours: 24, escalationAfterHours: 12 },
        { severity: "WARNING", acknowledgeWithinHours: 1,
          resolveWithinHours: 2, escalationAfterHours: 1 },
        { severity: "INFO", acknowledgeWithinHours: 1,
          resolveWithinHours: 2, escalationAfterHours: 1 },
      ],
    }, later)).toThrow();
  });
});
describe("review escalation queue", () => {
  it("generates escalation for overdue required review", () => {
    const policy = parseIntegrityReviewDeadlinePolicy(undefined,
      "2026-11-05T00:00:00.000Z");
    const deadlines = evaluateIntegrityReviewDeadlines(
      queue, replayIntegrityReviewEvents(queue, []), [], policy);
    const report = buildIntegrityReviewEscalations(
      queue, deadlines, null, null);
    expect(report.totals.critical).toBe(1);
    expect(report.escalations[0]?.notificationDispatched).toBe(false);
  });
  it("filters escalation by reason", () => {
    const policy = parseIntegrityReviewDeadlinePolicy(undefined,
      "2026-11-05T00:00:00.000Z");
    const deadlines = evaluateIntegrityReviewDeadlines(
      queue, replayIntegrityReviewEvents(queue, []), [], policy);
    const report = buildIntegrityReviewEscalations(
      queue, deadlines, null, null);
    const page = queryIntegrityReviewEscalations(report,
      parseIntegrityReviewEscalationQuery({
        reasons: ["ESCALATION_DEADLINE"],
      }));
    expect(page.total).toBe(1);
  });
  it("rejects unknown escalation policy flags", () => {
    expect(() => parseIntegrityReviewEscalationPolicy({
      dispatchNotifications: true,
    })).toThrow();
  });
});
