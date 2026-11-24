import { describe, expect, it } from "vitest";
import {
  planIncidentEscalations, verifyEscalationPlan, escalationDigest,
  validateEscalationPolicy, evaluateEscalationDispatch,
  createEscalationQueue, validateEscalationQueue,
  applyEscalationQueueTransition, compareEscalationPlans,
  groupEscalationsByOwner, exportEscalationPlanCSV,
  summarizeEscalationPlan, assessEscalationAssignment,
  type EscalationPolicy,
} from "./incident-escalation-dispatch-domain";
import type { AssuranceHandoffBoard, AssuranceHandoff } from
  "./incident-assurance-handoff-domain";

const now = "2026-11-24T12:00:00.000Z";
const earlier = "2026-11-24T09:00:00.000Z";
const before = "2026-11-24T10:00:00.000Z";
const after = "2026-11-24T13:00:00.000Z";
const boardId = "board-escalation-test";
const incidentId = "incident-escalation-test";
const organizationId = "organization-escalation-test";
const actorId = "actor-admin-test";
const rule = {
  id: "rule-escalation-p0",
  priority: "P0" as const,
  status: "UNASSIGNED" as const,
  trigger: "UNASSIGNED_AGE" as const,
  minimumAgeMinutes: 30,
  warningMinutes: 60,
  maximumFrequencyMinutes: 60,
  escalationLevel: 2 as const,
  recommendedRole: "OWNER" as const,
  requireIndependentReview: true,
};
const policy: EscalationPolicy = {
  schema: "cyberpilot.incident.escalation.policy.v1",
  id: "policy-escalation-test",
  effectiveAt: "2026-01-01T00:00:00.000Z",
  rules: [rule], concurrencyPerTenant: 2,
  maxDispatchesPerCycle: 20, minReevaluationMinutes: 30,
  schedulingHorizonMinutes: 1440,
  riskAcceptedForInternalReadOnly: true,
  externalNotificationsAllowed: false, providerWritesAllowed: false,
};
const handoff: AssuranceHandoff = {
  id: "handoff-escalation-test",
  controlId: "control-escalation-test",
  category: "ACCESS", controlState: "UNKNOWN",
  importance: "CRITICAL", priority: "P0",
  suggestedOwnerRole: "OWNER", guidance: "Review locally",
  dueAt: before,
  assignedUserId: null, assignedBy: null, assignedAt: null,
  acceptedBy: null, acceptedAt: null,
  status: "UNASSIGNED", revision: 1, updatedAt: earlier,
  escalationCount: 0, lastEscalatedAt: null,
  needsEvidence: ["independent-observation"],
  evidenceReferences: [], notes: [],
  independentlyVerifiedProviderOutcome: false,
  externallyNotified: false, externalWrites: 0,
};
function board(patch: Partial<AssuranceHandoffBoard> = {}):
  AssuranceHandoffBoard {
  return {
    schema: "cyberpilot.incident.assurance.handoff-board.v1",
    id: boardId, organizationId, incidentId, incidentRevision: 1,
    situationDigest: "a".repeat(64), assuranceDigest: "b".repeat(64),
    policyId: "policy-01", createdAt: earlier, updatedAt: earlier,
    createdBy: actorId, revision: 1, status: "ACTIVE",
    handoffs: [handoff], sourceCoverage: "PARTIAL",
    unknownCount: 1, criticalFailures: 1,
    nextReviewBy: after, supersededBy: null,
    providerContainmentVerified: false, providerWrites: 0,
    notificationsDispatched: 0,
    ...patch,
  };
}
function plan(boards = [board()], at = now) {
  return planIncidentEscalations({
    organizationId, incidentId, policy, boards, at,
  });
}
describe("incident escalation planning and safe durable state", () => {
  it("rejects policy permitting external writes", () => {
    expect(validateEscalationPolicy(policy)).toEqual([]);
    expect(validateEscalationPolicy({ ...policy,
      externalNotificationsAllowed: true as never }))
      .toContain("ESCALATION_EXTERNAL_PERMISSION_FORGED");
    expect(validateEscalationPolicy({ ...policy,
      rules: [rule, rule] })).toContain("ESCALATION_RULE_ID_INVALID");
  });
  it("generates one deterministic read-only review dispatch", () => {
    const p = plan();
    expect(verifyEscalationPlan(p)).toEqual([]);
    expect(p.dispatches).toHaveLength(1);
    expect(p.eligible).toBe(1);
    expect(p.dispatches[0]?.authorizedProviderMutations).toBe(0);
    expect(p.dispatches[0]?.notificationDeliveries).toBe(0);
    expect(p.dispatches[0]?.payload.internalOnly).toBe(true);
    expect(p.dispatches[0]?.payload.boardDigest)
      .toBe(escalationDigest(board()));
    expect(p.candidates[0]?.boardDigest)
      .toBe(p.dispatches[0]?.payload.boardDigest);
    expect(plan().dispatches[0]?.idempotencyKey)
      .toBe(p.dispatches[0]?.idempotencyKey);
  });
  it("does not schedule future or terminal boards", () => {
    expect(plan([board({ status: "CLOSED_INTERNAL" })])
      .dispatches).toHaveLength(0);
    const future = board({ createdAt: after,
      handoffs: [{ ...handoff, updatedAt: after }] });
    expect(plan([future]).dispatches).toHaveLength(0);
  });
  it("rejects cross-tenant boards and duplicated identities", () => {
    expect(() => plan([board({
      organizationId: "organization-other",
    })])).toThrow("ESCALATION_CROSS_TENANT_BOARD");
    expect(() => plan([board(), board()]))
      .toThrow("ESCALATION_DUPLICATE_BOARD");
  });
  it("respects explicit cooldown and never duplicates per handoff", () => {
    const first = plan([board({
      handoffs: [{ ...handoff, lastEscalatedAt: before }],
    })]);
    expect(first.dispatches).toHaveLength(1);
    const second = plan([board({
      handoffs: [{ ...handoff, lastEscalatedAt: now }],
    })]);
    expect(second.dispatches).toHaveLength(0);
    expect(second.candidates[0]?.reason).toBe("COOLDOWN");
  });
  it("rechecks immutable board revision during job execution", () => {
    const p = plan();
    const dispatch = p.dispatches[0]!;
    const good = evaluateEscalationDispatch({
      dispatch, policy, board: board(), at: now,
    });
    expect(good.status).toBe("STILL_ACTIONABLE");
    expect(good.providerWrites).toBe(0);
    expect(good.externalNotificationDispatched).toBe(false);
    const stale = evaluateEscalationDispatch({
      dispatch, policy, board: board({ revision: 2 }), at: now,
    });
    expect(stale.status).toBe("STALE_SNAPSHOT");
    expect(stale.canEscalateInternally).toBe(false);
  });
  it("starts a revision-one queue ledger that rejects forged outcomes", () => {
    const p = plan();
    const { snapshot, event } = createEscalationQueue(
      p.dispatches[0]!, actorId, now);
    expect(validateEscalationQueue(snapshot, [event])).toEqual([]);
    expect(snapshot.externallyExecuted).toBe(false);
    expect(validateEscalationQueue({ ...snapshot,
      externallyExecuted: true as never }, [event]))
      .toContain("ESCALATION_QUEUE_EXTERNAL_CLAIM");
  });
  it("applies queue transitions with CAS and immutable event chains", () => {
    const p = plan();
    const { snapshot, event } = createEscalationQueue(
      p.dispatches[0]!, actorId, now);
    const a = applyEscalationQueueTransition(snapshot, [event], {
      expectedRevision: 1, actorId,
      at: now, state: "ADMITTED",
    });
    expect(a.snapshot.revision).toBe(2);
    expect(validateEscalationQueue(a.snapshot, [event, a.event]))
      .toEqual([]);
    expect(() => applyEscalationQueueTransition(a.snapshot,
      [event, a.event], {
        expectedRevision: 1, actorId, at: now, state: "CLAIMED",
      })).toThrow("ESCALATION_QUEUE_CAS_REJECTED");
  });
  it("blocks unauthorized state transitions and false execution receipt", () => {
    const p = plan();
    const { snapshot, event } = createEscalationQueue(
      p.dispatches[0]!, actorId, now);
    expect(() => applyEscalationQueueTransition(snapshot, [event], {
      expectedRevision: 1, actorId,
      at: now, state: "OBSERVED",
    })).toThrow("ESCALATION_QUEUE_TRANSITION_DENIED");
  });
  it("reports internal changes without claiming provider actions", () => {
    const first = plan();
    const second = plan([], after);
    const diff = compareEscalationPlans(first, second);
    expect(diff.removed).toHaveLength(1);
    expect(diff.externalNotificationDelta).toBe(0);
    expect(groupEscalationsByOwner(first)[0]?.owner).toBe("UNASSIGNED");
    expect(summarizeEscalationPlan(first).noProviderControlChanges)
      .toBe(true);
    expect(exportEscalationPlanCSV(first))
      .toContain("idempotencyKey");
    expect(escalationDigest({ a: 1, b: 2 }))
      .toBe(escalationDigest({ b: 2, a: 1 }));
  });
  it("classifies revoked assignments without granting write authority", () => {
    const results = assessEscalationAssignment(
      board({ handoffs: [{
        ...handoff, assignedUserId: "user-revoked",
        status: "ASSIGNED",
      }] }), new Map());
    expect(results[0]?.eligibility).toBe("REVOKED");
    expect(results[0]?.memberScopeConfirmed).toBe(false);
  });
});
