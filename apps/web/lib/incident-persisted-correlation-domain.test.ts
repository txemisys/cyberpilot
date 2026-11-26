import { describe, it, expect } from "vitest";
import {
  beginCorrelationBoard, applyCorrelationBoard,
  validateCorrelationBoardPayload, summarizeCorrelationBoard,
  correlationReviewIntegrityMatrix,
} from "./incident-persisted-correlation-domain";
import { verifyCoordinationHistory, coordinationDigest } from
  "./incident-coordination-ledger-domain";
import type { CorrelationReport } from
  "./incident-crosscase-correlation-domain";
const org = "org-review-correlation";
const one = "incident-case-one";
const two = "incident-case-two";
const actor = "reviewer-alice";
const peer = "reviewer-bob-test";
const at = "2026-11-26T09:00:00.000Z";
const digest = "a".repeat(64);
const evidence = (incidentId: string) => ({
  incidentId, source: "INCIDENT" as const,
  sourceId: incidentId, eventIds: ["event-test-one"],
  eventCount: 1, firstAt: at, lastAt: at,
  integrity: "INCOMPLETE" as const,
  provenance: "LOCAL_TIMELINE" as const,
});
const report: CorrelationReport = {
  schema: "cyberpilot.incident.correlation.report.v1",
  organizationId: org, requestedAt: at,
  selectedIncidentIds: [one, two],
  policyDigest: digest, selectionDigest: digest, digest,
  cases: [], findings: [{
    id: "corr-candidate-one", kind: "SHARED_ACTOR",
    strength: "WEAK", priority: "P2",
    leftIncidentId: one, rightIncidentId: two,
    explanation: "The same internal responder appears in both histories",
    evidence: [evidence(one), evidence(two)],
    sharedValueFingerprint: digest,
    identityEquivalenceEstablished: false,
    compromiseEstablished: false,
    providerOutcomeVerified: false, manualReviewRequired: true,
  }],
  totalCandidateLinks: 1, resultsTruncated: false,
  completeness: "PARTIAL", weakestEvidenceLevel: "WEAK",
  warnings: [], externalActions: 0,
  providerIdentityConfirmed: false,
  providerContainmentConfirmed: false,
};
const start = () => beginCorrelationBoard({
  recordId: "correlation-board-test", organizationId: org,
  incidentId: one, actorId: actor, commandId: "create-correlation-one",
  at, report,
});
const reason = "Independent explanation of candidate internal linkage";
function mutate(
  prior: ReturnType<typeof start>,
  action: Parameters<typeof applyCorrelationBoard>[1]["action"],
  actorId = actor, commandId = "change-correlation-one",
  atTime = "2026-11-26T09:10:00.000Z",
) {
  return applyCorrelationBoard(prior.snapshot, {
    organizationId: org, incidentId: one,
    kind: "CORRELATION", recordId: prior.snapshot.id,
    commandId, expectedRevision: prior.snapshot.revision,
    actorId, role: "ADMIN", at: atTime, action,
  }, prior.event.eventDigest);
}
const hypothesisId = "hypothesis:" +
  coordinationDigest("corr-candidate-one").slice(0, 36);
describe("persistent correlation review", () => {
  it("initializes local candidate board with auditable creation", () => {
    const created = start();
    expect(validateCorrelationBoardPayload(created.snapshot.payload))
      .toEqual([]);
    expect(verifyCoordinationHistory(created.snapshot, [created.event]))
      .toEqual([]);
    expect(summarizeCorrelationBoard(created.snapshot)
      .identityConfirmedByProvider).toBe(false);
  });
  it("blocks unassigned analysis and closing an open candidate", () => {
    const created = start();
    expect(() => mutate(created, {
      kind: "START", hypothesisId, reason,
    })).toThrow("CORRELATION_START_DENIED");
    expect(() => mutate(created, {
      kind: "CLOSE", reason,
    })).toThrow("CORRELATION_CLOSE_UNRESOLVED_OR_TRUNCATED");
  });
  it("demands an alternative explanation and evidence before submission", () => {
    const assigned = mutate(start(), {
      kind: "ASSIGN", hypothesisId,
      assigneeId: actor, reason,
    });
    const started = mutate(assigned, {
      kind: "START", hypothesisId, reason,
    }, actor, "start-correlation-one");
    expect(() => mutate(started, {
      kind: "SUBMIT", hypothesisId, reason,
    }, actor, "submit-correlation-one")).toThrow(
      "CORRELATION_SUBMISSION_INCOMPLETE");
    const alternate = mutate(started, {
      kind: "ALTERNATIVE", hypothesisId, reason,
    }, actor, "alt-correlation-one");
    const withEvidence = mutate(alternate, {
      kind: "ADD_EVIDENCE", hypothesisId,
      evidenceId: "evidence-correlation-one", incidentId: one,
      reference: "internal-event-1234",
      sourceCategory: "LOCAL_AUDIT", scopeChecked: true, reason,
    }, actor, "proof-correlation-one");
    expect(correlationReviewIntegrityMatrix(withEvidence.snapshot)[0]
      ?.evidenceCount).toBe(1);
    const submitted = mutate(withEvidence, {
      kind: "SUBMIT", hypothesisId, reason,
    }, actor, "submit-correlation-two");
    expect(() => mutate(submitted, {
      kind: "DECIDE", hypothesisId,
      conclusion: "SUPPORTED_INTERNAL", reason,
    }, actor, "review-same-actor")).toThrow(
      "CORRELATION_REVIEW_INDEPENDENCE_DENIED");
    const reviewed = mutate(submitted, {
      kind: "DECIDE", hypothesisId,
      conclusion: "SUPPORTED_INTERNAL", reason,
    }, peer, "review-correlation-one");
    expect(reviewed.snapshot.payload.hypotheses[0]?.locallyCorrelated)
      .toBe(true);
    expect(reviewed.snapshot.payload.hypotheses[0]?.compromiseEstablished)
      .toBe(false);
    expect(reviewed.snapshot.payload.providerCompromisesConfirmed).toBe(0);
  });
  it("rejects inconsistent cross-tenant source and unsupported provider outcome", () => {
    expect(() => beginCorrelationBoard({
      recordId: "other-review-one", organizationId: "org-other",
      incidentId: one, actorId: actor,
      commandId: "create-other-one", at, report,
    })).toThrow("CORRELATION_SOURCE_UNSAFE");
    const value = start();
    expect(validateCorrelationBoardPayload({
      ...value.snapshot.payload,
      providerCompromisesConfirmed: 1 as never,
    })).toContain("CORRELATION_BOARD_EXTERNAL_CLAIM_FORGED");
  });
});
