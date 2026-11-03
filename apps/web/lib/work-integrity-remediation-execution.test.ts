import { describe, expect, it } from "vitest";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import { buildIntegrityRemediationWorkspace } from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationExecutionEvents,
  buildIntegrityRemediationExecutionLedger,
  verifyIntegrityRemediationExecutionEvidence,
  queryIntegrityRemediationExecution,
  parseIntegrityRemediationExecutionQuery,
  compareIntegrityRemediationExecutionLedgers,
} from "./work-integrity-remediation-execution";
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
const accepted = [{
  candidateId, decision: "ACCEPT" as const, reason: "Approved",
  reviewerId: "reviewer", reviewedAt: "2026-11-01T00:00:00.000Z",
}];
const event = (state: string, eventId: string, day: number, evidenceRefs: string[] = []) => ({
  eventId, candidateId, state, attemptId: "attempt-one",
  occurredAt: `2026-11-${String(day).padStart(2, "0")}T00:00:00.000Z`,
  actorUserId: "actor-one", evidenceRefs, reason: "Reviewed",
});
describe("integrity remediation execution", () => {
  it("rejects invalid event shapes", () => {
    expect(() => parseIntegrityRemediationExecutionEvents([
      event("INVALID", "event-one", 2),
    ])).toThrow();
  });
  it("requires approval before starting execution", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
    ]);
    const result = buildIntegrityRemediationExecutionLedger(plan, [], events);
    expect(result.totals.errors).toBe(1);
    expect(result.totals.notStarted).toBe(plan.candidates.length);
  });
  it("allows an approved request to begin", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
    ]);
    const result = buildIntegrityRemediationExecutionLedger(plan, accepted, events);
    expect(result.totals.requested).toBe(1);
    expect(result.totals.errors).toBe(0);
  });
  it("requires evidence references before completion", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
      event("IN_PROGRESS", "event-two", 3),
      event("COMPLETED", "event-three", 4),
    ]);
    const result = buildIntegrityRemediationExecutionLedger(plan, accepted, events);
    expect(result.totals.completed).toBe(0);
    expect(result.findings.map(x => x.code)).toContain("MISSING_EVIDENCE");
  });
  it("distinguishes claimed evidence from verified evidence", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
      event("IN_PROGRESS", "event-two", 3),
      event("COMPLETED", "event-three", 4, ["trusted-ref"]),
    ]);
    const result = buildIntegrityRemediationExecutionLedger(plan, accepted, events);
    expect(result.totals.completed).toBe(1);
    expect(result.totals.verifiedCompleted).toBe(0);
    const verified = verifyIntegrityRemediationExecutionEvidence(
      result, ["trusted-ref"]);
    expect(verified.totals.verifiedCompleted).toBe(1);
  });
  it("rejects illegal state transitions", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
      event("COMPLETED", "event-two", 3, ["evidence"]),
    ]);
    const result = buildIntegrityRemediationExecutionLedger(plan, accepted, events);
    expect(result.findings.map(x => x.code)).toContain("INVALID_TRANSITION");
  });
  it("rejects duplicate event IDs", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
      event("IN_PROGRESS", "event-one", 3),
    ]);
    const result = buildIntegrityRemediationExecutionLedger(plan, accepted, events);
    expect(result.findings.map(x => x.code)).toContain("DUPLICATE_EVENT");
  });
  it("paginates execution states", () => {
    const result = buildIntegrityRemediationExecutionLedger(plan, [], []);
    const page = queryIntegrityRemediationExecution(result,
      parseIntegrityRemediationExecutionQuery({
        states: ["NOT_STARTED"], limit: 1,
      }));
    expect(page.candidates).toHaveLength(1);
    expect(page.total).toBe(plan.candidates.length);
  });
  it("reports newly verified executions", () => {
    const events = parseIntegrityRemediationExecutionEvents([
      event("REQUESTED", "event-one", 2),
      event("IN_PROGRESS", "event-two", 3),
      event("COMPLETED", "event-three", 4, ["trusted-ref"]),
    ]);
    const before = buildIntegrityRemediationExecutionLedger(plan, accepted, events);
    const after = verifyIntegrityRemediationExecutionEvidence(
      before, ["trusted-ref"]);
    const diff = compareIntegrityRemediationExecutionLedgers(before, after);
    expect(diff.newlyVerified).toContain(candidateId);
  });
});
