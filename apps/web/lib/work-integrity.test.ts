import { describe, expect, it } from "vitest";
import {
  INTEGRITY_CODES,
  encodeIntegrityCursor,
  inspectIntegrityWork,
  parseIntegrityQuery,
  type IntegrityWork,
  type IntegrityFinding,
} from "./work-integrity";

const baseline = new Date("2026-10-25T12:00:00.000Z");
const updated = new Date("2026-10-26T12:00:00.000Z");
const now = new Date("2026-10-31T12:00:00.000Z");
const scope = "organization_one";
const person = "person_001";
const otherPerson = "person_002";
const allComplete = {
  eventsComplete: true,
  checklistComplete: true,
  evidenceComplete: true,
  handoffsComplete: true,
};
const members = new Set([person, otherPerson]);
function record(): IntegrityWork {
  return {
    id: "work_00001",
    organizationId: scope,
    findingId: "finding_001",
    remediationId: "remediation_001",
    assigneeUserId: person,
    status: "IN_PROGRESS",
    revision: 2,
    createdAt: baseline,
    updatedAt: updated,
    completedAt: null,
    dueAt: new Date("2026-11-10T12:00:00.000Z"),
    finding: { organizationId: scope },
    remediation: { organizationId: scope, findingId: "finding_001" },
    events: [
      {
        id: "event_002",
        kind: "UPDATED",
        occurredAt: updated,
        before: { status: "TODO", revision: 1 },
        after: {
          status: "IN_PROGRESS",
          revision: 2,
          assigneeUserId: person,
          completedAt: null,
          dueAt: "2026-11-10T12:00:00.000Z",
        },
      },
      {
        id: "event_001",
        kind: "CREATED",
        occurredAt: baseline,
        before: null,
        after: {
          status: "TODO",
          revision: 1,
          assigneeUserId: person,
          completedAt: null,
          dueAt: "2026-11-10T12:00:00.000Z",
        },
      },
    ],
    checklist: [{
      id: "check_001",
      completedAt: updated,
      completedByUserId: person,
    }],
    evidenceLinks: [{
      id: "link_001",
      evidenceId: "evidence_001",
      unlinkedAt: null,
      unlinkedByUserId: null,
      evidence: { organizationId: scope },
    }],
    handoffs: [{
      id: "handoff_001",
      recipientUserId: person,
      status: "ACCEPTED",
      decidedAt: updated,
      decidedByUserId: otherPerson,
      expiresAt: null,
    }],
  };
}
function review(item: IntegrityWork, coverage = allComplete): IntegrityFinding[] {
  return inspectIntegrityWork(item, members, now, coverage);
}
function codes(item: IntegrityWork, coverage = allComplete): string[] {
  return review(item, coverage).map(issue => issue.code);
}
function includesOnly(item: IntegrityWork, expected: string, coverage = allComplete) {
  expect(codes(item, coverage)).toContain(expected);
}
describe("work integrity audit", () => {
  it("treats the consistent baseline as having no findings", () => {
    expect(review(record())).toEqual([]);
  });
  it("publishes stable, unique codes", () => {
    expect(new Set(INTEGRITY_CODES).size).toBe(INTEGRITY_CODES.length);
    expect(INTEGRITY_CODES.length).toBeGreaterThan(20);
  });
  it("never changes the object being inspected", () => {
    const item = record();
    const original = JSON.stringify(item);
    review(item);
    expect(JSON.stringify(item)).toBe(original);
  });
  it("does not equate work completion with security verification", () => {
    const item = record();
    item.status = "DONE";
    item.completedAt = updated;
    item.events[0]!.after = {
      status: "DONE", revision: 2, assigneeUserId: person,
      dueAt: item.dueAt!.toISOString(), completedAt: updated.toISOString(),
    };
    expect(codes(item)).toEqual([]);
  });
  it("does not equate being in progress with incomplete evidence", () => {
    const item = record();
    item.status = "IN_PROGRESS";
    expect(codes(item)).toEqual([]);
  });
  it("does not guess membership histories for former assignees", () => {
    const item = record();
    item.assigneeUserId = "former_member";
    includesOnly(item, "ASSIGNEE_NOT_MEMBER");
  });
  it("recognizes a missing assignee without raising an anomaly", () => {
    const item = record();
    item.assigneeUserId = null;
    item.events[0]!.after = {
      status: "IN_PROGRESS", revision: 2, assigneeUserId: null,
      dueAt: item.dueAt!.toISOString(), completedAt: null,
    };
    expect(codes(item)).toEqual(["HANDOFF_ASSIGNEE_DIVERGENCE"]);
  });
  it("detects a cross-organization finding reference", () => {
    const item = record();
    item.finding.organizationId = "another_org";
    includesOnly(item, "FINDING_MISMATCH");
  });
  it("detects a cross-organization remediation reference", () => {
    const item = record();
    item.remediation.organizationId = "another_org";
    includesOnly(item, "FINDING_MISMATCH");
  });
  it("detects a remediation pointing at a different finding", () => {
    const item = record();
    item.remediation.findingId = "different_finding";
    includesOnly(item, "FINDING_MISMATCH");
  });
  it("marks done without timestamp", () => {
    const item = record();
    item.status = "DONE";
    includesOnly(item, "DONE_WITHOUT_COMPLETION");
  });
  it.each(["TODO", "IN_PROGRESS", "BLOCKED", "CANCELLED"])(
    "marks completion timestamp remaining in %s",
    status => {
      const item = record();
      item.status = status;
      item.completedAt = updated;
      includesOnly(item, "OPEN_WITH_COMPLETION");
    },
  );
  it("detects completion before creation", () => {
    const item = record();
    item.completedAt = new Date("2026-01-01T00:00:00.000Z");
    includesOnly(item, "COMPLETION_BEFORE_CREATION");
  });
  it("detects retrospective deadlines for optional review", () => {
    const item = record();
    item.dueAt = new Date("2026-01-01T00:00:00.000Z");
    includesOnly(item, "DEADLINE_BEFORE_CREATION");
  });
  it("does not flag a future deadline", () => {
    const item = record();
    item.dueAt = new Date("2027-01-01T00:00:00.000Z");
    expect(codes(item)).not.toContain("DEADLINE_BEFORE_CREATION");
  });
  it("recognizes missing creation events when all events are loaded", () => {
    const item = record();
    item.events = item.events.filter(event => event.kind !== "CREATED");
    includesOnly(item, "MISSING_CREATE_EVENT");
  });
  it("does not claim creation event is missing for truncated history", () => {
    const item = record();
    item.events = item.events.filter(event => event.kind !== "CREATED");
    expect(codes(item, { ...allComplete, eventsComplete: false }))
      .not.toContain("MISSING_CREATE_EVENT");
  });
  it("detects an event before creation", () => {
    const item = record();
    item.events[1]!.occurredAt = new Date("2020-01-01T00:00:00.000Z");
    includesOnly(item, "EVENT_TIME_ORDER");
  });
  it("detects a future revision snapshot", () => {
    const item = record();
    item.events[0]!.after = {
      status: "IN_PROGRESS", revision: 99, assigneeUserId: person,
      dueAt: item.dueAt!.toISOString(), completedAt: null,
    };
    includesOnly(item, "EVENT_REVISION_AHEAD");
  });
  it("detects a missing mutation snapshot", () => {
    const item = record();
    item.events[0]!.after = null;
    includesOnly(item, "INVALID_EVENT_SNAPSHOT");
  });
  it("detects array mutation snapshot as invalid", () => {
    const item = record();
    item.events[0]!.after = ["incorrect"];
    includesOnly(item, "INVALID_EVENT_SNAPSHOT");
  });
  it("detects latest mutation inconsistency", () => {
    const item = record();
    item.events[0]!.after = {
      status: "BLOCKED", revision: 2, assigneeUserId: person,
      dueAt: item.dueAt!.toISOString(), completedAt: null,
    };
    includesOnly(item, "EVENT_SNAPSHOT_MISMATCH");
  });
  it("does not compare obsolete snapshots against the latest item", () => {
    const item = record();
    item.events[1]!.after = { status: "TODO", revision: 1 };
    expect(codes(item)).toEqual([]);
  });
  it("handles a later comment without misclassifying the snapshot", () => {
    const item = record();
    item.events.push({
      id: "event_003", kind: "COMMENTED",
      occurredAt: new Date("2026-10-27T12:00:00.000Z"),
      before: null, after: null,
    });
    expect(codes(item)).toEqual([]);
  });
  it("detects a mutation after stored updatedAt", () => {
    const item = record();
    item.events[0]!.occurredAt = new Date("2026-10-28T12:00:00.000Z");
    includesOnly(item, "EVENT_AFTER_LAST_UPDATE");
  });
  it("skips all event checks on incomplete event history", () => {
    const item = record();
    item.events[0]!.after = null;
    item.events[1]!.occurredAt = new Date("2020-01-01T00:00:00.000Z");
    expect(codes(item, { ...allComplete, eventsComplete: false }))
      .not.toContain("INVALID_EVENT_SNAPSHOT");
    expect(codes(item, { ...allComplete, eventsComplete: false }))
      .not.toContain("EVENT_TIME_ORDER");
  });
  it("detects orphaned checklist completer", () => {
    const item = record();
    item.checklist[0]!.completedByUserId = "former_member";
    includesOnly(item, "CHECKLIST_COMPLETER_MISMATCH");
  });
  it("recognizes unattributed checklist completion", () => {
    const item = record();
    item.checklist[0]!.completedByUserId = null;
    includesOnly(item, "CHECKLIST_COMPLETED_WITHOUT_ACTOR");
  });
  it("recognizes checklist attribution without completion", () => {
    const item = record();
    item.checklist[0]!.completedAt = null;
    includesOnly(item, "CHECKLIST_ACTOR_WITHOUT_COMPLETION");
  });
  it("does not flag missing checklist actor for incomplete, untouched entry", () => {
    const item = record();
    item.checklist = [{ id: "check_002", completedAt: null, completedByUserId: null }];
    expect(codes(item)).toEqual([]);
  });
  it("withholds checklist checks for saturated collection", () => {
    const item = record();
    item.checklist[0]!.completedByUserId = "former_member";
    const flagged = codes(item, { ...allComplete, checklistComplete: false });
    expect(flagged).not.toContain("CHECKLIST_COMPLETER_MISMATCH");
  });
  it("detects cross-tenant evidence links", () => {
    const item = record();
    item.evidenceLinks[0]!.evidence = { organizationId: "other_tenant" };
    includesOnly(item, "EVIDENCE_ORGANIZATION_MISMATCH");
  });
  it("detects inaccessible linked evidence", () => {
    const item = record();
    item.evidenceLinks[0]!.evidence = null;
    includesOnly(item, "EVIDENCE_LINK_MISSING_TARGET");
  });
  it("detects unlink date without actor", () => {
    const item = record();
    item.evidenceLinks[0]!.unlinkedAt = now;
    includesOnly(item, "EVIDENCE_UNLINKED_WITHOUT_ACTOR");
  });
  it("detects unlink actor without date", () => {
    const item = record();
    item.evidenceLinks[0]!.unlinkedByUserId = person;
    includesOnly(item, "EVIDENCE_UNLINK_ACTOR_WITHOUT_DATE");
  });
  it("allows a fully attributed unlink", () => {
    const item = record();
    item.evidenceLinks[0]!.unlinkedByUserId = person;
    item.evidenceLinks[0]!.unlinkedAt = now;
    expect(codes(item)).toEqual([]);
  });
  it("withholds evidence checks when collection saturated", () => {
    const item = record();
    item.evidenceLinks[0]!.evidence = { organizationId: "other_tenant" };
    expect(codes(item, { ...allComplete, evidenceComplete: false }))
      .not.toContain("EVIDENCE_ORGANIZATION_MISMATCH");
  });
  it("flags handoff to no-longer-member recipient", () => {
    const item = record();
    item.handoffs[0]!.recipientUserId = "former_member";
    includesOnly(item, "HANDOFF_RECIPIENT_NOT_MEMBER");
  });
  it("flags handoff decision without date", () => {
    const item = record();
    item.handoffs[0]!.decidedAt = null;
    includesOnly(item, "HANDOFF_DECISION_INCOMPLETE");
  });
  it("flags handoff decision without actor", () => {
    const item = record();
    item.handoffs[0]!.decidedByUserId = null;
    includesOnly(item, "HANDOFF_DECISION_INCOMPLETE");
  });
  it("flags pending handoff with decision time", () => {
    const item = record();
    item.handoffs[0]!.status = "REQUESTED";
    includesOnly(item, "HANDOFF_UNDECIDED_WITH_DECISION");
  });
  it("flags an expired pending handoff", () => {
    const item = record();
    item.handoffs[0] = {
      id: "handoff_001", recipientUserId: person,
      status: "REQUESTED", decidedAt: null,
      decidedByUserId: null, expiresAt: baseline,
    };
    includesOnly(item, "HANDOFF_EXPIRED_PENDING");
  });
  it("does not flag a pending handoff that has not expired", () => {
    const item = record();
    item.handoffs[0] = {
      id: "handoff_001", recipientUserId: person,
      status: "REQUESTED", decidedAt: null,
      decidedByUserId: null, expiresAt: new Date("2027-01-01T00:00:00.000Z"),
    };
    expect(codes(item)).toEqual([]);
  });
  it("detects an accepted handoff diverging from current assignee", () => {
    const item = record();
    item.handoffs[0]!.recipientUserId = otherPerson;
    includesOnly(item, "HANDOFF_ASSIGNEE_DIVERGENCE");
  });
  it("does not mistake declined handoff for assignee inconsistency", () => {
    const item = record();
    item.handoffs[0]!.status = "DECLINED";
    item.handoffs[0]!.recipientUserId = otherPerson;
    expect(codes(item)).toEqual([]);
  });
  it("withholds handoff signals on truncated collection", () => {
    const item = record();
    item.handoffs[0]!.recipientUserId = "former_member";
    expect(codes(item, { ...allComplete, handoffsComplete: false }))
      .not.toContain("HANDOFF_RECIPIENT_NOT_MEMBER");
  });
  it("includes a concrete work and resource identifier for each signal", () => {
    const item = record();
    item.handoffs[0]!.status = "REQUESTED";
    for (const finding of review(item)) {
      expect(finding.workItemId).toBe(item.id);
      expect(finding.resourceId.length).toBeGreaterThan(0);
      expect(finding.message.length).toBeGreaterThan(10);
      expect(finding.recommendation.length).toBeGreaterThan(10);
    }
  });
  it("exposes severity from a bounded vocabulary", () => {
    const item = record();
    item.assigneeUserId = "former_member";
    item.finding.organizationId = "other_org";
    for (const issue of review(item)) {
      expect(["critical", "attention", "info"]).toContain(issue.severity);
    }
  });
});
describe("work integrity cursor filters", () => {
  it("defaults to a bounded first page without info", () => {
    expect(parseIntegrityQuery({})).toEqual({
      limit: 25, cursor: null, includeInfo: false,
    });
  });
  it.each([1, 5, 10, 25, 50, 100])(
    "accepts bounded page size %d",
    limit => expect(parseIntegrityQuery({ limit: String(limit) }).limit).toBe(limit),
  );
  it.each([-1, 0, 101, 999, 2.5, NaN, Infinity, "unlimited", "1.1"])(
    "rejects invalid page size %s",
    limit => expect(() => parseIntegrityQuery({ limit })).toThrow(),
  );
  it("allows explicit informational signal inclusion", () => {
    expect(parseIntegrityQuery({ includeInfo: "true" }).includeInfo).toBe(true);
    expect(parseIntegrityQuery({ includeInfo: "false" }).includeInfo).toBe(false);
  });
  it.each(["TRUE", "1", 1, true, null, "other"])(
    "rejects ambiguous includeInfo input %s",
    includeInfo => expect(() => parseIntegrityQuery({ includeInfo })).toThrow(),
  );
  it("round trips an updatedAt/id cursor", () => {
    const cursor = { updatedAt: updated, id: "work_00001" };
    expect(parseIntegrityQuery({ cursor: encodeIntegrityCursor(cursor) }).cursor)
      .toEqual(cursor);
  });
  it("round trips the year boundary correctly", () => {
    const cursor = {
      updatedAt: new Date("2026-12-31T23:59:59.999Z"), id: "work_00002",
    };
    expect(parseIntegrityQuery({ cursor: encodeIntegrityCursor(cursor) }).cursor)
      .toEqual(cursor);
  });
  it("accepts a collision timestamp with deterministic id suffix", () => {
    const cursor = parseIntegrityQuery({
      cursor: "2026-10-26T12:00:00.000Z.work_00001",
    }).cursor;
    expect(cursor?.id).toBe("work_00001");
    expect(cursor?.updatedAt.toISOString()).toBe(updated.toISOString());
  });
  it.each([
    "",
    "2026-10-26",
    "2026-10-26T12:00:00Z.work_00001",
    "2026-10-26T12:00:00.000Z.",
    "2026-10-26T12:00:00.000Z.bad!",
    "2026-02-30T12:00:00.000Z.work_00001",
    "2026-10-26T12:00:00.000+00:00.work_00001",
  ])("rejects malformed cursor %s", cursor => {
    expect(() => parseIntegrityQuery({ cursor })).toThrow();
  });
  it("rejects nonstring cursor", () => {
    expect(() => parseIntegrityQuery({ cursor: { id: "work_00001" } })).toThrow();
  });
  it("rejects huge cursor", () => {
    expect(() => parseIntegrityQuery({ cursor: "x".repeat(500) })).toThrow();
  });
});
