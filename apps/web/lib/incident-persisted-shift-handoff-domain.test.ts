import { describe, it, expect } from "vitest";
import { coordinationDigest, verifyCoordinationHistory } from
  "./incident-coordination-ledger-domain";
import {
  beginShiftHandoff, applyShiftHandoff,
  validateShiftHandoffPayload, summarizeShiftHandoff,
  shiftHandoffContinuityMatrix, compareShiftHandoffSnapshots,
} from "./incident-persisted-shift-handoff-domain";
import type { ShiftBriefing } from "./incident-shift-briefing-domain";
const digest = "a".repeat(64);
const org = "org-shift-acceptance";
const incident = "incident-shift-acceptance";
const alice = "operator-shift-alice";
const bob = "operator-shift-bobby";
const at = "2026-11-26T08:00:00.000Z";
const reason = "Internally reviewed shift status and outstanding work";
const brief = (): ShiftBriefing => ({
  schema: "cyberpilot.incident.shift.briefing.v1",
  organizationId: org, incidentId: incident,
  incidentRevision: 5,
  window: {
    shiftId: "shift-morning-test",
    startsAt: "2026-11-26T07:00:00.000Z",
    endsAt: "2026-11-26T09:00:00.000Z",
    evaluatedAt: at, outgoingRole: "ADMIN", incomingRole: "ADMIN",
    outgoingUserId: alice, incomingUserId: null,
    acknowledgedBy: null, acceptedAt: null,
  },
  policyDigest: digest, forensicDigest: digest,
  investigationDigest: digest,
  activity: [], sourceInventory: [],
  workItems: [{
    id: "shift-work-item-one", incidentId: incident,
    urgency: "BEFORE_END", priority: "P1",
    category: "VERIFY_SOURCE_CHAIN", source: "INCIDENT",
    sourceId: incident, assignedRole: "ADMIN",
    assignedUserId: null, explanation: reason,
    dueAt: "2026-11-26T09:00:00.000Z",
    evidenceReferences: [], evidenceNeeded: [],
    underlyingTaskIds: [], internalStatus: "PROPOSED",
    providerWritePermitted: false, externallyVerified: false,
  }],
  watchpoints: [{
    id: "watchpoint-source-one", category: "INTEGRITY",
    priority: "P1", source: "INCIDENT",
    trigger: "SOURCE_REVIEW_REQUIRED", explanation: reason,
    recommendedRole: "ADMIN", requiresIndependentConfirmation: true,
  }],
  workTruncated: false, activityTruncated: false,
  watchpointsTruncated: false, sourceEvents: 1,
  openEvidenceRequests: 1,
  priorityCounts: { P0: 0, P1: 1, P2: 0, P3: 0 },
  completeness: "PARTIAL", operationalConfidence: "LOCAL_ONLY",
  limitations: [], digest,
  receiptIssued: false, handoffAcknowledged: false,
  externalActions: 0,
  providerOutcomesIndependentlyVerified: false,
});
const begin = () => beginShiftHandoff({
  recordId: "shift-handoff-test", organizationId: org,
  incidentId: incident, actorId: alice,
  incomingUserId: bob, commandId: "shift-create-one",
  at, briefing: brief(),
});
function change(
  previous: ReturnType<typeof begin>,
  action: Parameters<typeof applyShiftHandoff>[1]["action"],
  actorId = alice, commandId = "shift-command-one",
  atTime = "2026-11-26T08:10:00.000Z",
) {
  return applyShiftHandoff(previous.snapshot, {
    organizationId: org, incidentId: incident, recordId: previous.snapshot.id,
    kind: "SHIFT", commandId, expectedRevision: previous.snapshot.revision,
    actorId, role: "ADMIN", at: atTime, action,
  }, previous.event.eventDigest);
}
describe("persistent shift operator handoff", () => {
  it("creates a bounded local-only handoff with valid hashed event", () => {
    const created = begin();
    expect(validateShiftHandoffPayload(created.snapshot.payload))
      .toEqual([]);
    expect(verifyCoordinationHistory(created.snapshot, [created.event]))
      .toEqual([]);
    expect(summarizeShiftHandoff(created.snapshot)
      .providerOutcomeVerified).toBe(false);
  });
  it("refuses self-acceptance and early submission without work review", () => {
    expect(() => beginShiftHandoff({
      recordId: "shift-self-reference", organizationId: org,
      incidentId: incident, actorId: alice,
      incomingUserId: alice, commandId: "shift-create-two",
      at, briefing: brief(),
    })).toThrow("SHIFT_HANDOFF_SOURCE_INVALID");
    const created = begin();
    expect(() => change(created, {
      kind: "SUBMIT", reason,
    })).toThrow("SHIFT_HANDOFF_WORK_UNREVIEWED");
  });
  it("only incoming operator can accept the exact submitted digest", () => {
    const created = begin();
    const reviewed = change(created, {
      kind: "MARK_REVIEWED", workId: "shift-work-item-one", reason,
    }, alice, "mark-reviewed-one");
    expect(shiftHandoffContinuityMatrix(reviewed.snapshot)[0]
      ?.reviewedByOutgoing).toBe(true);
    const submitted = change(reviewed, {
      kind: "SUBMIT", reason,
    }, alice, "submit-shift-one", "2026-11-26T08:11:00.000Z");
    expect(() => change(submitted, {
      kind: "ACCEPT", expectedSubmittedDigest:
        coordinationDigest(submitted.snapshot), reason,
    }, alice, "self-accept-shift-one", "2026-11-26T08:12:00.000Z"))
      .toThrow("SHIFT_HANDOFF_STALE_OR_UNAUTHORIZED_RESPONSE");
    expect(() => change(submitted, {
      kind: "ACCEPT", expectedSubmittedDigest: digest, reason,
    }, bob, "stale-accept-shift-one", "2026-11-26T08:12:00.000Z"))
      .toThrow("SHIFT_HANDOFF_STALE_OR_UNAUTHORIZED_RESPONSE");
    const accepted = change(submitted, {
      kind: "ACCEPT",
      expectedSubmittedDigest: coordinationDigest(submitted.snapshot), reason,
    }, bob, "accept-shift-one", "2026-11-26T08:12:00.000Z");
    expect(accepted.snapshot.payload.accepted?.reviewedBy).toBe(bob);
    expect(accepted.snapshot.payload.providerWrites).toBe(0);
    expect(accepted.snapshot.payload.accepted?.providerContainmentConfirmed)
      .toBe(false);
    expect(compareShiftHandoffSnapshots(submitted.snapshot,
      accepted.snapshot).acceptedNow).toBe(true);
  });
  it("allows returning a submission without fabricating acceptance", () => {
    const created = begin();
    const reviewed = change(created, {
      kind: "MARK_REVIEWED", workId: "shift-work-item-one", reason,
    }, alice, "mark-reviewed-two");
    const submitted = change(reviewed, {
      kind: "SUBMIT", reason,
    }, alice, "submit-shift-two", "2026-11-26T08:11:00.000Z");
    const returned = change(submitted, {
      kind: "RETURN",
      expectedSubmittedDigest: coordinationDigest(submitted.snapshot),
      category: "MISSING_EVIDENCE", reason,
    }, bob, "return-shift-one", "2026-11-26T08:12:00.000Z");
    expect(returned.snapshot.payload.status).toBe("RETURNED");
    expect(returned.snapshot.payload.accepted).toBeNull();
    expect(returned.snapshot.payload.returned).toHaveLength(1);
  });
  it("rejects forged provider claims and mixed-tenant commands", () => {
    const created = begin();
    expect(validateShiftHandoffPayload({
      ...created.snapshot.payload, providerWrites: 1 as never,
    })).toContain("SHIFT_HANDOFF_FALSE_EXTERNAL_CLAIM");
    expect(() => applyShiftHandoff(created.snapshot, {
      organizationId: "org-another", incidentId: incident,
      recordId: created.snapshot.id, kind: "SHIFT",
      commandId: "shift-foreign-command", actorId: alice,
      role: "ADMIN", at: "2026-11-26T08:10:00.000Z",
      expectedRevision: 1,
      action: { kind: "ADD_NOTE", noteId: "note-foreign-one",
        workId: null, category: "RISK", reason },
    }, created.event.eventDigest)).toThrow(
      "COORDINATION_CROSS_TENANT_OR_RECORD");
  });
});
