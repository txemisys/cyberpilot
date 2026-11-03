import { describe, expect, it } from "vitest";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import { buildIntegrityRemediationWorkspace } from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationExecutionEvents,
  buildIntegrityRemediationExecutionLedger,
} from "./work-integrity-remediation-execution";
import { buildIntegrityExecutionReviewAudit } from "./work-integrity-remediation-execution-review";
import {
  reconcileIntegrityExecutionEvidence,
} from "./work-integrity-remediation-evidence-provenance";
import {
  evaluateIntegrityExecutionControls,
} from "./work-integrity-remediation-execution-controls";
import {
  evaluateIntegrityExecutionReadiness,
  parseIntegrityExecutionReadinessPolicy,
  parseIntegrityExecutionReadinessQuery,
  queryIntegrityExecutionReadiness,
  compareIntegrityExecutionReadiness,
} from "./work-integrity-remediation-execution-readiness";
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
  candidateId, decision: "ACCEPT" as const,
  reason: "Approved", reviewerId: "reviewer",
  reviewedAt: "2026-11-01T00:00:00.000Z",
}];
const events = parseIntegrityRemediationExecutionEvents([
  {
    eventId: "event-one", candidateId, state: "REQUESTED",
    attemptId: "attempt-one", occurredAt: "2026-11-02T00:00:00.000Z",
    actorUserId: "actor-one", evidenceRefs: [], reason: "Start",
  },
  {
    eventId: "event-two", candidateId, state: "IN_PROGRESS",
    attemptId: "attempt-one", occurredAt: "2026-11-03T00:00:00.000Z",
    actorUserId: "actor-one", evidenceRefs: [], reason: "Working",
  },
  {
    eventId: "event-three", candidateId, state: "COMPLETED",
    attemptId: "attempt-one", occurredAt: "2026-11-04T00:00:00.000Z",
    actorUserId: "actor-two", evidenceRefs: ["link-one"], reason: "Done",
  },
]);
const ledger = buildIntegrityRemediationExecutionLedger(plan, decisions, events);
const audit = buildIntegrityExecutionReviewAudit(ledger, events);
const links = [{
  auditId: "link-one", originalAuditId: null,
  action: "LINK" as const, captureId: plan.captureId,
  caseKey: "case-one", workItemId: "work-one",
  actorUserId: "reviewer", occurredAt: "2026-11-02T12:00:00.000Z",
}];
const provenance = reconcileIntegrityExecutionEvidence(
  plan, ledger, audit, events, links);
const controls = evaluateIntegrityExecutionControls(
  plan, decisions, events, ledger, audit, "2026-11-05T00:00:00.000Z");
describe("integrity execution readiness", () => {
  it("does not confuse provenance with independent security verification", () => {
    const result = evaluateIntegrityExecutionReadiness(
      plan, ledger, controls, provenance);
    expect(result.totals.ready).toBe(0);
    expect(result.candidates[0]?.blockers).toContain("UNVERIFIED_EVIDENCE");
  });
  it("filters candidates blocked by missing verification", () => {
    const result = evaluateIntegrityExecutionReadiness(
      plan, ledger, controls, provenance);
    const page = queryIntegrityExecutionReadiness(result,
      parseIntegrityExecutionReadinessQuery({
        blockers: ["UNVERIFIED_EVIDENCE"], onlyBlocked: true,
      }));
    expect(page.total).toBeGreaterThan(0);
  });
  it("rejects contradictory readiness query filters", () => {
    expect(() => parseIntegrityExecutionReadinessQuery({
      onlyReady: true, onlyBlocked: true,
    })).toThrow();
  });
  it("rejects unknown readiness policy fields", () => {
    expect(() => parseIntegrityExecutionReadinessPolicy({
      trustClientClaim: true,
    })).toThrow();
  });
  it("reports stable deltas for unchanged evidence", () => {
    const first = evaluateIntegrityExecutionReadiness(
      plan, ledger, controls, provenance);
    const second = evaluateIntegrityExecutionReadiness(
      plan, ledger, controls, provenance);
    const delta = compareIntegrityExecutionReadiness(first, second);
    expect(delta.readyDelta).toBe(0);
    expect(delta.readinessLost).toHaveLength(0);
  });
});
