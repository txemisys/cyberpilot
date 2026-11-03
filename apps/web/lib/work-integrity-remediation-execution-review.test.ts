import { describe, expect, it } from "vitest";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import { buildIntegrityRemediationWorkspace } from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationExecutionEvents,
  buildIntegrityRemediationExecutionLedger,
} from "./work-integrity-remediation-execution";
import {
  buildIntegrityExecutionReviewHistory,
  buildIntegrityExecutionReviewAudit,
  buildIntegrityExecutionReviewMatrix,
  parseIntegrityExecutionReviewQuery,
  queryIntegrityExecutionReview,
} from "./work-integrity-remediation-execution-review";

const input = {
  captureId: "capture-one",
  policies: [parseIntegrityEvidenceCoveragePolicy({
    captureId: "capture-one",
    rules: [{
      id: "required", caseKey: "case-one",
      minimumActiveWorkItems: 1, requiredWorkItemIds: ["work-one"],
    }],
  })],
};
const plan = buildIntegrityRemediationWorkspace(input, []).plan;
const candidateId = plan.candidates[0]!.id;
const decisions = [{
  candidateId, decision: "ACCEPT" as const, reason: "Approved",
  reviewerId: "reviewer", reviewedAt: "2026-11-01T00:00:00.000Z",
}];
const events = parseIntegrityRemediationExecutionEvents([
  {
    eventId: "event-one", candidateId, state: "REQUESTED",
    attemptId: "attempt-one", occurredAt: "2026-11-02T00:00:00.000Z",
    actorUserId: "actor-one", evidenceRefs: [], reason: "Requested",
  },
  {
    eventId: "event-two", candidateId, state: "IN_PROGRESS",
    attemptId: "attempt-one", occurredAt: "2026-11-03T00:00:00.000Z",
    actorUserId: "actor-two", evidenceRefs: [], reason: "Started",
  },
  {
    eventId: "event-three", candidateId, state: "COMPLETED",
    attemptId: "attempt-one", occurredAt: "2026-11-04T00:00:00.000Z",
    actorUserId: "actor-two", evidenceRefs: ["evidence-one"], reason: "Done",
  },
]);
describe("integrity execution review", () => {
  it("builds a chronological execution history", () => {
    const history = buildIntegrityExecutionReviewHistory(
      plan, decisions, events, [
        "2026-11-01T00:00:00.000Z",
        "2026-11-03T12:00:00.000Z",
        "2026-11-05T00:00:00.000Z",
      ]);
    expect(history.checkpoints).toHaveLength(3);
    expect(history.checkpoints[0]?.ledger.totals.notStarted)
      .toBe(plan.candidates.length);
    expect(history.checkpoints[2]?.ledger.totals.completed).toBe(1);
    expect(history.summary.totalTransitions).toBeGreaterThan(0);
  });
  it("does not claim evidence verification from client event references", () => {
    const history = buildIntegrityExecutionReviewHistory(
      plan, decisions, events, ["2026-11-05T00:00:00.000Z"]);
    expect(history.final.totals.completed).toBe(1);
    expect(history.final.totals.verifiedCompleted).toBe(0);
  });
  it("attributes accepted events to their actors", () => {
    const ledger = buildIntegrityRemediationExecutionLedger(
      plan, decisions, events);
    const audit = buildIntegrityExecutionReviewAudit(ledger, events);
    expect(audit.totals.accepted).toBe(3);
    expect(audit.totals.actors).toBe(2);
    expect(audit.actors.find(x => x.actorUserId === "actor-two")
      ?.acceptedEvents).toBe(2);
  });
  it("returns the attempt lifecycle in the audit", () => {
    const ledger = buildIntegrityRemediationExecutionLedger(
      plan, decisions, events);
    const audit = buildIntegrityExecutionReviewAudit(ledger, events);
    expect(audit.attempts[0]?.latestState).toBe("COMPLETED");
    expect(audit.attempts[0]?.evidenceRefs).toContain("evidence-one");
  });
  it("filters and paginates accepted events", () => {
    const ledger = buildIntegrityRemediationExecutionLedger(
      plan, decisions, events);
    const audit = buildIntegrityExecutionReviewAudit(ledger, events);
    const query = parseIntegrityExecutionReviewQuery({
      actorUserIds: ["actor-two"], accepted: true, limit: 1,
    });
    const page = queryIntegrityExecutionReview(audit, query);
    expect(page.total).toBe(2);
    expect(page.events).toHaveLength(1);
    expect(page.hasMore).toBe(true);
  });
  it("rejects reversed checkpoint intervals", () => {
    expect(() => parseIntegrityExecutionReviewQuery({
      from: "2026-11-05T00:00:00.000Z",
      to: "2026-11-02T00:00:00.000Z",
    })).toThrow();
  });
  it("joins cases and work items from the authoritative plan", () => {
    const ledger = buildIntegrityRemediationExecutionLedger(
      plan, decisions, events);
    const matrix = buildIntegrityExecutionReviewMatrix(ledger, plan);
    expect(matrix.captureId).toBe(plan.captureId);
    expect(matrix.totals.unassigned + matrix.cases.reduce(
      (sum, x) => sum + x.total, 0)).toBeGreaterThan(0);
  });
});
