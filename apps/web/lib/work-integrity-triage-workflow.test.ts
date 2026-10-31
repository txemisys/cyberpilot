import { describe, expect, it } from "vitest";
import {
  canTransitionTriage,
  parseTriageCommand,
  projectTriageHistory,
  type TriageDecision,
  type TriageEvent,
} from "./work-integrity-triage";

/**
 * Domain contract checks for a review sequence. These exercises require no
 * external tenant and deliberately cannot certify or modify security controls.
 */
const time = (day: number) => new Date(`2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`);
const base = {
  organizationId: "tenant_00001",
  workItemId: "work_00001",
  actorUserId: "user_00001",
  code: "FINDING_MISMATCH" as const,
  resourceId: "finding_001",
  rationale: "Investigation recorded with explicit limitations.",
  reference: null,
  revision: 5,
};
function create(id: number, decision: TriageDecision, day: number,
  changes: Partial<TriageEvent> = {}): TriageEvent {
  return {
    ...base,
    id: `event_${String(id).padStart(5, "0")}`,
    occurredAt: time(day),
    decision,
    previousEventId: id > 1 ? `event_${String(id - 1).padStart(5, "0")}` : null,
    ...changes,
  };
}
function payload(value: Partial<Record<string, unknown>> = {}) {
  return {
    workItemId: base.workItemId,
    code: base.code,
    resourceId: base.resourceId,
    revision: base.revision,
    decision: "INVESTIGATE",
    rationale: base.rationale,
    reference: base.reference,
    expectedPreviousEventId: null,
    ...value,
  };
}
describe("long-running human review lifecycle", () => {
  it("tracks investigate, acknowledge, reopen and investigate chronologically", () => {
    const entries = [
      create(1, "INVESTIGATE", 21),
      create(2, "ACKNOWLEDGE", 22),
      create(3, "REOPEN", 23),
      create(4, "INVESTIGATE", 24),
    ];
    for (let i = 0; i < entries.length; i++) {
      expect(canTransitionTriage(entries[i - 1]?.decision ?? null, entries[i]!.decision))
        .toBe(true);
    }
    const [projection] = projectTriageHistory(entries, 5);
    expect(projection?.totalDecisions).toBe(4);
    expect(projection?.latestDecision).toBe("INVESTIGATE");
    expect(projection?.latestEventId).toBe("event_00004");
    expect(projection?.staleRevision).toBe(false);
    expect(projection?.history.map(x => x.id)).toEqual([
      "event_00004", "event_00003", "event_00002", "event_00001",
    ]);
  });
  it("supports a dismissed diagnostic subsequently reopened", () => {
    const sequence: TriageDecision[] = ["DISMISS", "REOPEN", "INVESTIGATE", "ACKNOWLEDGE"];
    let previous: TriageDecision | null = null;
    for (const decision of sequence) {
      expect(canTransitionTriage(previous, decision)).toBe(true);
      previous = decision;
    }
  });
  it("does not silently change the latest review when events are unordered", () => {
    const values = [create(3, "REOPEN", 23), create(1, "INVESTIGATE", 21),
      create(2, "ACKNOWLEDGE", 22)];
    expect(projectTriageHistory(values, 5)[0]?.latestDecision).toBe("REOPEN");
  });
  it("marks old reviews stale after a new work item revision", () => {
    const entries = [create(1, "INVESTIGATE", 21), create(2, "ACKNOWLEDGE", 22)];
    expect(projectTriageHistory(entries, 5)[0]?.staleRevision).toBe(false);
    expect(projectTriageHistory(entries, 6)[0]?.staleRevision).toBe(true);
  });
  it("does not reinterpret acknowledgement as remediation completion", () => {
    const result = projectTriageHistory([create(1, "ACKNOWLEDGE", 21)], 5)[0];
    expect(result?.latestDecision).toBe("ACKNOWLEDGE");
    expect(result).not.toHaveProperty("remediationStatus");
    expect(result).not.toHaveProperty("findingStatus");
    expect(result).not.toHaveProperty("securityScore");
  });
  it("separates independent diagnoses on the same task", () => {
    const entries = [
      create(1, "INVESTIGATE", 21),
      create(2, "ACKNOWLEDGE", 22),
      create(3, "INVESTIGATE", 23, { code: "ASSIGNEE_NOT_MEMBER", resourceId: "user_00001" }),
    ];
    const projections = projectTriageHistory(entries, 5);
    expect(projections).toHaveLength(2);
    expect(projections.map(p => p.code)).toContain("ASSIGNEE_NOT_MEMBER");
    expect(projections.map(p => p.code)).toContain("FINDING_MISMATCH");
  });
  it("separates one diagnostic on two different linked records", () => {
    const entries = [
      create(1, "INVESTIGATE", 21),
      create(2, "INVESTIGATE", 22, { resourceId: "finding_002" }),
    ];
    expect(projectTriageHistory(entries, 5)).toHaveLength(2);
  });
  it("does not merge the same resource across different work items", () => {
    const entries = [
      create(1, "INVESTIGATE", 21),
      create(2, "INVESTIGATE", 22, { workItemId: "work_00002" }),
    ];
    expect(projectTriageHistory(entries, 5)).toHaveLength(2);
  });
  it("keeps each event's actor identity distinct", () => {
    const entries = [
      create(1, "INVESTIGATE", 21),
      create(2, "ACKNOWLEDGE", 22, { actorUserId: "user_00002" }),
    ];
    const projected = projectTriageHistory(entries, 5)[0]!;
    expect(projected.latestActorUserId).toBe("user_00002");
    expect(projected.history[1]?.actorUserId).toBe("user_00001");
  });
  it("does not lose previous links when projecting history", () => {
    const entries = [
      create(1, "INVESTIGATE", 21),
      create(2, "ACKNOWLEDGE", 22),
      create(3, "REOPEN", 23),
    ];
    const projected = projectTriageHistory(entries, 5)[0]!;
    expect(projected.history.map(e => e.previousEventId)).toEqual([
      "event_00002", "event_00001", null,
    ]);
  });
  it("does not alter stored event timestamps", () => {
    const entries = [create(1, "INVESTIGATE", 21), create(2, "ACKNOWLEDGE", 22)];
    const before = entries.map(e => e.occurredAt.toISOString());
    projectTriageHistory(entries, 5);
    expect(entries.map(e => e.occurredAt.toISOString())).toEqual(before);
  });
});
describe("strict input boundaries for review history", () => {
  it("requires a human rationale for a dismissal", () => {
    expect(() => parseTriageCommand(payload({
      decision: "DISMISS", rationale: "",
    }))).toThrow();
  });
  it("requires a human rationale for an acknowledgement", () => {
    expect(() => parseTriageCommand(payload({
      decision: "ACKNOWLEDGE", rationale: "short",
    }))).toThrow();
  });
  it("requires a human rationale for reopening", () => {
    expect(() => parseTriageCommand(payload({
      decision: "REOPEN", rationale: "x",
    }))).toThrow();
  });
  it("allows an auditable explanation with punctuation", () => {
    const input = payload({
      rationale: "Investigated SEC-123: linked evidence requires source validation.",
    });
    expect(parseTriageCommand(input).rationale).toContain("SEC-123");
  });
  it("preserves reference text without interpreting a URL", () => {
    const reference = "https://tickets.example.test/SEC-123";
    expect(parseTriageCommand(payload({ reference })).reference).toBe(reference);
  });
  it("refuses unsupported client-selected review status", () => {
    expect(() => parseTriageCommand(payload({ decision: "RESOLVED" }))).toThrow();
  });
  it("refuses client-supplied record status", () => {
    expect(() => parseTriageCommand(payload({ status: "DONE" }))).toThrow();
  });
  it("refuses client-supplied event id", () => {
    expect(() => parseTriageCommand(payload({ id: "event_forged" }))).toThrow();
  });
  it("refuses client-supplied actor type", () => {
    expect(() => parseTriageCommand(payload({ actorType: "SYSTEM" }))).toThrow();
  });
  it("refuses client-supplied event timestamps", () => {
    expect(() => parseTriageCommand(payload({ occurredAt: time(31).toISOString() }))).toThrow();
  });
  it("refuses client-supplied verification time", () => {
    expect(() => parseTriageCommand(payload({ verifiedAt: time(31).toISOString() }))).toThrow();
  });
  it("refuses client-supplied organization membership role", () => {
    expect(() => parseTriageCommand(payload({ role: "OWNER" }))).toThrow();
  });
  it("allows a reference to the actual preceding event", () => {
    const parsed = parseTriageCommand(payload({
      expectedPreviousEventId: "event_00023",
    }));
    expect(parsed.expectedPreviousEventId).toBe("event_00023");
  });
  it("normalizes empty optional reference to null", () => {
    expect(parseTriageCommand(payload({ reference: "" })).reference).toBeNull();
  });
});
