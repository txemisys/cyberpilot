import { describe, expect, it } from "vitest";
import {
  TRIAGE_DECISIONS, TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE,
  parseTriageCommand, parseTriageQuery, hydrateTriageEvent,
  projectTriageHistory, canTransitionTriage, assertTriageTransition,
  triageDisposition, type TriageEvent,
} from "./work-integrity-triage";
import { INTEGRITY_CODES } from "./work-integrity";

const at = new Date("2026-10-31T12:00:00.000Z");
function command() {
  return {
    workItemId: "work_00001", code: "FINDING_MISMATCH",
    resourceId: "finding_001", revision: 2,
    decision: "INVESTIGATE",
    rationale: "Investigate this stored operational discrepancy.",
    reference: null, expectedPreviousEventId: null,
  };
}
function history(overrides: Partial<TriageEvent> = {}): TriageEvent {
  return {
    id: "event_00001", organizationId: "tenant_00001",
    workItemId: "work_00001", actorUserId: "user_00001",
    occurredAt: at, decision: "INVESTIGATE", code: "FINDING_MISMATCH",
    resourceId: "finding_001", revision: 2,
    rationale: "Review relationships", reference: null,
    previousEventId: null, ...overrides,
  };
}
describe("integrity decision input", () => {
  it("accepts a complete valid decision", () => {
    expect(parseTriageCommand(command())).toMatchObject(command());
  });
  it.each(TRIAGE_DECISIONS)("supports %s as a review decision", decision => {
    expect(parseTriageCommand({ ...command(), decision }).decision).toBe(decision);
  });
  it.each(INTEGRITY_CODES)("supports known code %s", code => {
    expect(parseTriageCommand({ ...command(), code }).code).toBe(code);
  });
  it.each([0, -1, 2.2, 2147483648, "2", null, Infinity])(
    "rejects invalid revision %s",
    revision => expect(() => parseTriageCommand({ ...command(), revision })).toThrow(),
  );
  it.each(["", "tiny", "a".repeat(2001)])(
    "rejects invalid rationale %s",
    rationale => expect(() => parseTriageCommand({ ...command(), rationale })).toThrow(),
  );
  it("rejects actor and organization impersonation fields", () => {
    expect(() => parseTriageCommand({ ...command(), actorUserId: "user_00002" })).toThrow();
    expect(() => parseTriageCommand({ ...command(), organizationId: "tenant_00002" })).toThrow();
  });
  it("rejects attempts to write a security verification status", () => {
    expect(() => parseTriageCommand({ ...command(), verification: "VERIFIED" })).toThrow();
  });
  it("rejects unknown decision and diagnostic code", () => {
    expect(() => parseTriageCommand({ ...command(), decision: "VERIFIED" })).toThrow();
    expect(() => parseTriageCommand({ ...command(), code: "NOT_KNOWN" })).toThrow();
  });
  it("accepts and trims a reference", () => {
    expect(parseTriageCommand({ ...command(), reference: " SEC-123 " }).reference).toBe("SEC-123");
  });
  it("rejects excessive reference length", () => {
    expect(() => parseTriageCommand({ ...command(), reference: "a".repeat(201) })).toThrow();
  });
  it("accepts previous decision id for optimistic updates", () => {
    expect(parseTriageCommand({ ...command(),
      expectedPreviousEventId: "event_00001",
    }).expectedPreviousEventId).toBe("event_00001");
  });
  it("rejects malformed optimistic previous decision id", () => {
    expect(() => parseTriageCommand({
      ...command(), expectedPreviousEventId: "bad!",
    })).toThrow();
  });
  it("does not mutate source input", () => {
    const source = command();
    const before = JSON.stringify(source);
    parseTriageCommand(source);
    expect(JSON.stringify(source)).toBe(before);
  });
});
describe("decision event decoding", () => {
  const raw = () => ({
    id: "event_00001", organizationId: "tenant_00001",
    resourceId: "work_00001", actorUserId: "user_00001",
    occurredAt: at, metadata: {
      schemaVersion: 1, code: "FINDING_MISMATCH",
      resourceId: "finding_001", revision: 2,
      decision: "INVESTIGATE", rationale: "Review relationships",
      reference: null, previousEventId: null,
    },
  });
  it("maps the persisted event into review history", () => {
    expect(hydrateTriageEvent(raw())).toEqual(history());
  });
  it("rejects missing metadata", () => {
    expect(hydrateTriageEvent({ ...raw(), metadata: null })).toBeNull();
  });
  it("rejects unknown diagnostic codes", () => {
    const value = raw();
    expect(hydrateTriageEvent({
      ...value, metadata: { ...value.metadata, code: "UNKNOWN" },
    })).toBeNull();
  });
  it("rejects invalid revision metadata", () => {
    const value = raw();
    expect(hydrateTriageEvent({
      ...value, metadata: { ...value.metadata, revision: 2.5 },
    })).toBeNull();
  });
  it("retains server-provided organization rather than metadata organization", () => {
    const value = raw();
    const decoded = hydrateTriageEvent({
      ...value, metadata: { ...value.metadata, organizationId: "another" },
    });
    expect(decoded?.organizationId).toBe("tenant_00001");
  });
});
describe("review lifecycle", () => {
  it("does not permit reopening before first decision", () => {
    expect(canTransitionTriage(null, "REOPEN")).toBe(false);
  });
  it("allows first investigation", () => {
    expect(canTransitionTriage(null, "INVESTIGATE")).toBe(true);
  });
  it("allows acknowledgement after investigation", () => {
    expect(canTransitionTriage("INVESTIGATE", "ACKNOWLEDGE")).toBe(true);
  });
  it("requires reopening before overwriting closed decision", () => {
    expect(canTransitionTriage("DISMISS", "ACKNOWLEDGE")).toBe(false);
    expect(canTransitionTriage("DISMISS", "REOPEN")).toBe(true);
  });
  it("permits reassessment after reopening", () => {
    expect(canTransitionTriage("REOPEN", "INVESTIGATE")).toBe(true);
  });
  it("raises conflict on forbidden transition", () => {
    expect(() => assertTriageTransition(null, "REOPEN")).toThrow();
  });
  it.each(TRIAGE_DECISIONS)("exposes descriptive decision %s", decision => {
    expect(triageDisposition(decision).length).toBeGreaterThan(5);
  });
});
describe("audit projection", () => {
  it("maintains linked resource boundaries", () => {
    expect(projectTriageHistory([
      history(), history({ id: "event_00002", resourceId: "finding_002" }),
    ], 2)).toHaveLength(2);
  });
  it("groups multiple decisions about one diagnostic", () => {
    const result = projectTriageHistory([
      history(),
      history({ id: "event_00002", decision: "ACKNOWLEDGE",
        occurredAt: new Date("2026-11-01T12:00:00.000Z") }),
    ], 2);
    expect(result[0]?.totalDecisions).toBe(2);
    expect(result[0]?.latestDecision).toBe("ACKNOWLEDGE");
  });
  it("marks decisions stale when the work item revision changes", () => {
    expect(projectTriageHistory([history()], 3)[0]?.staleRevision).toBe(true);
  });
  it("does not mutate source audit events", () => {
    const events = [history(), history({ id: "event_00002" })];
    const before = JSON.stringify(events);
    projectTriageHistory(events, 2);
    expect(JSON.stringify(events)).toBe(before);
  });
  it("reports no conclusion without events", () => {
    expect(projectTriageHistory([], 1)).toEqual([]);
  });
});
describe("audit list filters", () => {
  it("defaults to bounded page one", () => {
    expect(parseTriageQuery({})).toEqual({
      page: 1, limit: 25, workItemId: null, code: null,
    });
  });
  it.each([-1, 0, 101, Infinity, "wrong"])(
    "rejects invalid limit %s", limit => {
      expect(() => parseTriageQuery({ limit })).toThrow();
    },
  );
  it("filters by exact work item and diagnostic code", () => {
    expect(parseTriageQuery({
      workItemId: "work_00001", code: "FINDING_MISMATCH",
    })).toMatchObject({
      workItemId: "work_00001", code: "FINDING_MISMATCH",
    });
  });
  it("rejects unknown codes and malformed ids", () => {
    expect(() => parseTriageQuery({ code: "NOT_A_CODE" })).toThrow();
    expect(() => parseTriageQuery({ workItemId: "bad!" })).toThrow();
  });
  it("uses a distinct immutable audit namespace", () => {
    expect(TRIAGE_AUDIT_ACTION).toBe("WORK_INTEGRITY_TRIAGE_REVIEWED");
    expect(TRIAGE_RESOURCE_TYPE).toBe("RemediationWorkItem");
  });
});
