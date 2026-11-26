import { describe, it, expect } from "vitest";
import {
  beginInvestigationReview, applyInvestigationReview,
  summarizeInvestigationReview, investigationEvidenceGapMatrix,
  validateInvestigationReviewPayload,
} from "./incident-persisted-investigation-domain";
import {
  verifyCoordinationHistory,
} from "./incident-coordination-ledger-domain";
import type { InvestigationCasebook } from
  "./incident-timeline-investigation-domain";
const digest = "a".repeat(64);
const at = "2026-11-26T10:00:00.000Z";
const org = "org-investigation-testing";
const incident = "incident-investigation-testing";
const alice = "operator-alice-test";
const bob = "operator-bobby-test";
const casebook: InvestigationCasebook = {
  schema: "cyberpilot.incident.timeline.investigation.v1",
  organizationId: org, incidentId: incident,
  generatedAt: at, sourceReportDigest: digest,
  inventoryComplete: true, signals: [], requests: [], tasks: [{
    id: "task-investigation-one",
    signalIds: [], priority: "P1", workstream: "LEDGER_INTEGRITY",
    status: "WAITING_FOR_EVIDENCE", assignedRole: "ADMIN",
    description: "Review local timeline anomalies",
    evidenceRequestIds: ["request-evidence-one"],
    manualOnly: true, ownerUserId: null,
    providerWriteAuthorized: false, proofOfContainment: false,
  }],
  priorityCounts: { P0: 0, P1: 1, P2: 0, P3: 0 },
  workstreamCounts: {
    LEDGER_INTEGRITY: 1, PROVENANCE: 0, RESPONSE_COORDINATION: 0,
    TABLETOP_VALIDATION: 0, ASSURANCE_FOLLOWUP: 0, COVERAGE: 0,
  },
  limitations: [], completeness: "PARTIAL",
  externalWrites: 0, providerOutcomesVerified: false, digest,
};
const start = () => beginInvestigationReview({
  recordId: "review-persistent-one", incidentId: incident,
  organizationId: org, actorId: alice, commandId: "command-create-one",
  at, casebook, incidentRevision: 1,
});
function mutate(
  prior: ReturnType<typeof start>, action:
    Parameters<typeof applyInvestigationReview>[1]["action"],
  actorId = alice, commandId = "command-test-one", atTime =
    "2026-11-26T10:10:00.000Z",
) {
  return applyInvestigationReview(prior.snapshot, {
    organizationId: org, incidentId: incident,
    recordId: prior.snapshot.id, kind: "INVESTIGATION",
    commandId, actorId, role: "ADMIN",
    expectedRevision: prior.snapshot.revision, at: atTime, action,
  }, prior.event.eventDigest);
}
const reason = "Investigación interna documentada y revisada";
describe("persisted forensic investigation", () => {
  it("creates bounded ledger with no forged external outcomes", () => {
    const value = start();
    expect(validateInvestigationReviewPayload(value.snapshot.payload))
      .toEqual([]);
    expect(verifyCoordinationHistory(value.snapshot, [value.event]))
      .toEqual([]);
    expect(summarizeInvestigationReview(value.snapshot)
      .providerActionsConfirmed).toBe(0);
  });
  it("rejects missing work and closing before independent review", () => {
    const value = start();
    expect(() => mutate(value, {
      kind: "CLOSE", reason,
    })).toThrow("INVESTIGATION_CLOSE_UNREVIEWED_WORK");
    expect(() => mutate(value, {
      kind: "START", workId: "task-unknown-work", reason,
    })).toThrow("INVESTIGATION_WORK_NOT_FOUND");
  });
  it("enforces assignee and state before collecting evidence", () => {
    const value = start();
    expect(() => mutate(value, {
      kind: "START", workId: "task-investigation-one", reason,
    })).toThrow("INVESTIGATION_START_ASSIGNEE_OR_STATE");
    const assigned = mutate(value, {
      kind: "ASSIGN", workId: "task-investigation-one",
      assigneeId: alice, reason,
    });
    expect(assigned.snapshot.payload.work[0]?.assignedUserId)
      .toBe(alice);
    expect(assigned.snapshot.payload.work[0]?.status).toBe("ASSIGNED");
    expect(investigationEvidenceGapMatrix(assigned.snapshot)[0]
      ?.uncoveredRequestIds).toEqual(["request-evidence-one"]);
  });
  it("forbids review by same operator and unproven provider actions", () => {
    const created = start();
    const assigned = mutate(created, {
      kind: "ASSIGN", workId: "task-investigation-one",
      assigneeId: alice, reason,
    });
    const started = mutate(assigned, {
      kind: "START", workId: "task-investigation-one", reason,
    }, alice, "command-start-one", "2026-11-26T10:11:00.000Z");
    const evidenced = mutate(started, {
      kind: "ADD_EVIDENCE", workId: "task-investigation-one",
      evidenceId: "evidence-test-one", requestId: "request-evidence-one",
      evidenceKind: "OPERATOR_CONFIRMATION",
      reference: "log-record-1234",
      description: "Observed local source event",
      provenance: "INTERNAL", reason,
    }, alice, "command-evidence-one", "2026-11-26T10:12:00.000Z");
    const requested = mutate(evidenced, {
      kind: "SUBMIT_REVIEW", workId: "task-investigation-one", reason,
    }, alice, "command-request-one", "2026-11-26T10:13:00.000Z");
    expect(() => mutate(requested, {
      kind: "REVIEW", workId: "task-investigation-one",
      disposition: "SUFFICIENT_INTERNAL", reason,
    }, alice, "command-same-actor", "2026-11-26T10:14:00.000Z"))
      .toThrow("INVESTIGATION_REVIEW_INDEPENDENCE_DENIED");
    const reviewed = mutate(requested, {
      kind: "REVIEW", workId: "task-investigation-one",
      disposition: "SUFFICIENT_INTERNAL", reason,
    }, bob, "command-review-one", "2026-11-26T10:14:00.000Z");
    expect(reviewed.snapshot.payload.work[0]?.status)
      .toBe("REVIEWED_INTERNAL");
    expect(reviewed.snapshot.payload.independentContainmentProof)
      .toBe(false);
    expect(reviewed.event.externallyVerified).toBe(false);
  });
  it("rejects cross-tenant commands and stale revisions", () => {
    const initial = start();
    expect(() => applyInvestigationReview(initial.snapshot, {
      organizationId: "org-other-tenant", incidentId: incident,
      recordId: initial.snapshot.id, kind: "INVESTIGATION",
      commandId: "command-other-tenant", actorId: alice,
      role: "ADMIN", at: "2026-11-26T10:11:00.000Z",
      expectedRevision: 1,
      action: { kind: "CLOSE", reason },
    }, initial.event.eventDigest)).toThrow("COORDINATION_CROSS_TENANT_OR_RECORD");
    expect(() => applyInvestigationReview(initial.snapshot, {
      organizationId: org, incidentId: incident,
      recordId: initial.snapshot.id, kind: "INVESTIGATION",
      commandId: "command-revision-stale", actorId: alice,
      role: "ADMIN", at: "2026-11-26T10:11:00.000Z",
      expectedRevision: 8,
      action: { kind: "CLOSE", reason },
    }, initial.event.eventDigest)).toThrow(
      "INVESTIGATION_CLOSE_UNREVIEWED_WORK");
  });
});
