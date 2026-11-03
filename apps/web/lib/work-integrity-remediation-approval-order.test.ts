import { describe, expect, it } from "vitest";
import { parseIntegrityEvidenceCoveragePolicy } from "./work-integrity-evidence-coverage";
import { buildIntegrityRemediationWorkspace } from "./work-integrity-remediation-workspace";
import {
  parseIntegrityRemediationExecutionEvents,
  buildIntegrityRemediationExecutionLedger,
} from "./work-integrity-remediation-execution";
describe("execution approval chronology", () => {
  it("does not accept retroactive approval", () => {
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
      reviewedAt: "2026-11-04T00:00:00.000Z",
    }];
    const events = parseIntegrityRemediationExecutionEvents([{
      eventId: "event-one", candidateId, state: "REQUESTED",
      attemptId: "attempt-one", occurredAt: "2026-11-02T00:00:00.000Z",
      actorUserId: "actor-one", evidenceRefs: [], reason: "Requested",
    }]);
    const result = buildIntegrityRemediationExecutionLedger(
      plan, decisions, events);
    expect(result.totals.requested).toBe(0);
    expect(result.findings.map(x => x.code)).toContain("STALE_DECISION");
  });
});
