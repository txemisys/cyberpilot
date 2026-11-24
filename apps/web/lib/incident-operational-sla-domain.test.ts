import { describe, expect, it } from "vitest";
import {
  analyzeOperationalSla, slaDigest, validateOperationalSlaPolicy,
  calculateSlaDailyBuckets, calculateSlaActorWorkloads,
  forecastInternalDeadlines, assessIncidentOperationalHealth,
  buildSlaOperationalPriorityQueue, operationalSlaAuditEnvelope,
  compareOperationalSlaSnapshots, type OperationalSlaPolicy,
  type HandoffSlaEvidence,
} from "./incident-operational-sla-domain";
import { normalizeTimelineEvent,
  type TimelineEvent } from "./incident-operational-timeline-domain";

const org = "org-test-sla";
const incidentId = "incident-test-sla";
const at = "2026-11-24T12:00:00.000Z";
const hour = 60 * 60000;
const date = (offset: number) =>
  new Date(Date.parse(at) + offset * 60000).toISOString();
const D = "d".repeat(64);
const policy: OperationalSlaPolicy = {
  schema: "cyberpilot.incident.internal-sla.policy.v1",
  policyId: "policy-test-sla", effectiveAt: date(-1440),
  firstReviewTargetMinutes: 60,
  firstAssignmentTargetMinutes: 120,
  firstEscalationTargetMinutes: 240,
  followupWarningMinutes: 30,
  priorityTargetsMinutes: { P0: 60, P1: 120, P2: 360 },
  businessCalendar: "ELAPSED_UTC", externalServiceGuarantee: false,
};
function event(source: TimelineEvent["source"], operation: string,
  revision: number, timeOffset: number): TimelineEvent {
  return normalizeTimelineEvent({
    organizationId: org, incidentId, source,
    sourceId: source === "INCIDENT" ? incidentId : "source-" + source,
    sourceRevision: revision,
    eventId: "event-" + source + "-" + revision,
    actorUserId: "owner-sla-test", operation,
    occurredAt: date(timeOffset), priorState: null,
    nextState: "OPEN", priorDigest: null,
    nextDigest: D, sourceEventDigest:
      source === "INCIDENT" ? null : D,
    sourceIntegrity: "INCOMPLETE",
  });
}
const handoff: HandoffSlaEvidence = {
  boardId: "board-sla-test", handoffId: "handoff-sla-test",
  controlId: "control-test", priority: "P0",
  createdAt: date(-180), dueAt: date(-60), updatedAt: date(-180),
  assignedAt: null, acceptedAt: null, lastEscalatedAt: null,
  status: "UNASSIGNED", assignedUserId: null, externalWrites: 0,
};
const assess = (events: TimelineEvent[] = [], handoffs:
  HandoffSlaEvidence[] = [], asOf = at) => analyzeOperationalSla({
  organizationId: org, incidentId, incidentRevision: 1, asOf,
  policy, events, handoffs, inventoryComplete: true,
});
describe("conservative internal incident SLA analysis", () => {
  it("validates explicit targets and denies any external guarantee", () => {
    expect(validateOperationalSlaPolicy(policy)).toEqual([]);
    expect(validateOperationalSlaPolicy({ ...policy,
      externalServiceGuarantee: true as never }))
      .toContain("SLA_POLICY_EXTERNAL_CLAIM_DENIED");
    expect(validateOperationalSlaPolicy({ ...policy,
      firstReviewTargetMinutes: 0 }))
      .toContain("SLA_POLICY_TARGET_INVALID");
  });
  it("keeps missing incident creation as UNKNOWN", () => {
    const snapshot = assess();
    expect(snapshot.completeness).toBe("UNKNOWN");
    expect(snapshot.sourceIntegrity).toBe("INCOMPLETE");
    expect(snapshot.totals.unknown).toBe(3);
    expect(snapshot.signal).toBe("REVIEW_REQUIRED");
    expect(snapshot.providerContainmentVerified).toBe(false);
  });
  it("rejects cross-tenant events in analytical measures", () => {
    expect(() => assess([{
      ...event("INCIDENT", "CREATE", 1, -100),
      organizationId: "org-other",
    }])).toThrow("SLA_CROSS_TENANT_EVENT");
  });
  it("rejects duplicate event revisions and future events", () => {
    const e = event("INCIDENT", "CREATE", 1, -100);
    expect(() => assess([e, { ...e,
      eventId: "other-event" }])).toThrow("SLA_DUPLICATE_EVENT_REVISION");
    expect(() => assess([event("INCIDENT", "CREATE", 1, 10)]))
      .toThrow("SLA_EVENT_FUTURE_OR_INVALID");
  });
  it("measures internally observed delays without external claims", () => {
    const snapshot = assess([
      event("INCIDENT", "CREATE", 1, -180),
      event("SITUATION_REVIEW", "BEGIN_REVIEW", 1, -100),
      event("ASSURANCE_HANDOFF", "ASSIGN", 1, -50),
    ]);
    const review = snapshot.measurements.find(x =>
      x.metricId === "FIRST_INTERNAL_REVIEW");
    expect(review?.actualElapsedMinutes).toBe(80);
    expect(review?.disposition).toBe("OVERDUE");
    expect(review?.outcome).toBe("PARTIAL");
    expect(snapshot.providerContainmentVerified).toBe(false);
  });
  it("detects a late and unassigned persisted handoff", () => {
    const snapshot = assess([event("INCIDENT", "CREATE", 1, -180)],
      [handoff]);
    expect(snapshot.handoffSummary.unassigned).toBe(1);
    expect(snapshot.handoffSummary.pastExplicitDueAt).toBe(1);
    expect(snapshot.handoffSummary.staleUnassigned).toBe(1);
    expect(snapshot.signal).toBe("ACTION_REQUIRED");
    expect(assessIncidentOperationalHealth(snapshot, []).urgency)
      .toBe("CRITICAL");
  });
  it("calculates internal due windows without external dispatch", () => {
    const snapshot = assess([event("INCIDENT", "CREATE", 1, -180)],
      [handoff]);
    const windows = forecastInternalDeadlines(snapshot, [60, 30]);
    expect(windows.map(x => x.horizonMinutes)).toEqual([30, 60]);
    expect(windows[0]?.alreadyOverdue).toBeGreaterThan(0);
    expect(windows.every(x => x.noExternalExecution)).toBe(true);
    expect(buildSlaOperationalPriorityQueue(snapshot)[0]?.action)
      .toMatch(/REVIEW|REQUEST/);
  });
  it("groups daily observations and actor workload", () => {
    const e = [event("INCIDENT", "CREATE", 1, -100),
      event("ASSURANCE_HANDOFF", "ESCALATE_INTERNAL", 1, -90)];
    expect(calculateSlaDailyBuckets(e, date(-1440), at)
      .reduce((n, x) => n + x.events, 0)).toBe(2);
    const workloads = calculateSlaActorWorkloads(e);
    expect(workloads[0]?.totalEvents).toBe(2);
    expect(workloads[0]?.escalationEvents).toBe(1);
    expect(workloads[0]?.uncertainEvidenceEvents).toBe(2);
  });
  it("hashes JSONB key permutations and audits without false proof", () => {
    const snapshot = assess([event("INCIDENT", "CREATE", 1, -100)]);
    expect(snapshot.digest).toBe(slaDigest({
      ...snapshot, digest: undefined,
    }));
    const envelope = operationalSlaAuditEnvelope(snapshot);
    expect(envelope.independentProviderEvidence).toBe(false);
    expect(slaDigest({ b: 2, a: 1 }))
      .toBe(slaDigest({ a: 1, b: 2 }));
  });
  it("prohibits cross-incident comparisons and tampered snapshots", () => {
    const snapshot = assess([event("INCIDENT", "CREATE", 1, -100)]);
    expect(() => compareOperationalSlaSnapshots(snapshot, {
      ...snapshot, incidentId: "incident-other",
    })).toThrow("SLA_SNAPSHOT_DIGEST_INVALID");
    expect(() => buildSlaOperationalPriorityQueue({
      ...snapshot, digest: "a".repeat(64),
    })).toThrow("SLA_SNAPSHOT_DIGEST_INVALID");
  });
});
