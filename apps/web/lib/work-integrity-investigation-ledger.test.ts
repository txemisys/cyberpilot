import { describe, expect, it } from "vitest";
import type { InvestigationBacklog, InvestigationTask } from "./work-integrity-investigation-backlog";
import {
  DEFAULT_LEDGER_POLICY, validateLedgerPolicy, validateLedgerEvent,
  replayInvestigationLedger, compareInvestigationLedgers,
  investigationLedgerProgress, investigationLedgerCsv, investigationLedgerJson,
  type LedgerEvent, type InvestigationLedger,
} from "./work-integrity-investigation-ledger";
const at = "2026-10-31T10:00:00.000Z";
const later = "2026-10-31T10:01:00.000Z";
const latest = "2026-10-31T10:02:00.000Z";
const task = (id: string, dependsOn: string[] = []): InvestigationTask => ({
  id, caseKey: "case-" + id, workItemId: "work-" + id,
  kind: "REVIEW", priority: "P1", dependsOn,
  estimatedMinutes: 30, assignedAnalystId: "alice",
  rationale: "Review evidence", coverageComplete: true,
});
const backlog = (tasks: InvestigationTask[] = [task("a"), task("b", ["a"])],
  complete = true): InvestigationBacklog => ({
  version: 1, organizationId: "org-a", capturedAt: at,
  assessedAt: at, complete, tasks,
  byKind: { RECOLLECT: 0, REASSESS: 0, REVIEW: tasks.length,
    COMPLETE_EVIDENCE: 0, ALLOCATE_CAPACITY: 0, ESCALATE: 0, VERIFY: 0 },
  estimatedMinutes: tasks.reduce((sum, item) => sum + item.estimatedMinutes, 0),
  unassignedTasks: 0, warnings: [],
});
const event = (id: string, taskId: string,
  kind: LedgerEvent["kind"], time = at,
  evidenceReference: string | null = null): LedgerEvent => ({
  id, taskId, kind, at: time, actorId: "reviewer-1",
  rationale: "Verified case evidence", evidenceReference,
});
const replay = (events: LedgerEvent[], complete = true,
  policy = DEFAULT_LEDGER_POLICY) =>
  replayInvestigationLedger(backlog(undefined, complete), events, policy);
describe("ledger policy validation", () => {
  it("accepts default", () => {
    expect(validateLedgerPolicy(DEFAULT_LEDGER_POLICY).maximumEvents).toBe(100000);
  });
  it("rejects zero event limit", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, maximumEvents: 0,
    })).toThrow();
  });
  it("rejects excessive event limit", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, maximumEvents: 100001,
    })).toThrow();
  });
  it("rejects fractional event limit", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, maximumEvents: 1.5,
    })).toThrow();
  });
  it("rejects zero per-task limit", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, maximumEventsPerTask: 0,
    })).toThrow();
  });
  it("rejects excessive per-task limit", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, maximumEventsPerTask: 10001,
    })).toThrow();
  });
  it("rejects invalid evidence flag", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, requireEvidenceForCompletion: "yes" as never,
    })).toThrow();
  });
  it("rejects invalid partial flag", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, allowPartialSource: 1 as never,
    })).toThrow();
  });
  it("rejects invalid dependency flag", () => {
    expect(() => validateLedgerPolicy({
      ...DEFAULT_LEDGER_POLICY, enforceDependencies: null as never,
    })).toThrow();
  });
});
describe("event validation", () => {
  it("accepts valid event", () => {
    expect(validateLedgerEvent(event("1", "a", "START")).kind).toBe("START");
  });
  it("rejects blank event ID", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"), id: "" })).toThrow();
  });
  it("rejects blank task ID", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"), taskId: "" })).toThrow();
  });
  it("rejects blank actor ID", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"), actorId: "" })).toThrow();
  });
  it("rejects unknown event kind", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"),
      kind: "DELETE" as never })).toThrow();
  });
  it("rejects malformed timestamp", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"),
      at: "yesterday" })).toThrow();
  });
  it("rejects noncanonical timestamp", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"),
      at: "2026-02-30T10:00:00.000Z" })).toThrow();
  });
  it("rejects empty rationale", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"),
      rationale: " " })).toThrow();
  });
  it("rejects oversized rationale", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"),
      rationale: "x".repeat(4001) })).toThrow();
  });
  it("rejects empty evidence reference", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "COMPLETE"),
      evidenceReference: "" })).toThrow();
  });
  it("rejects control characters in IDs", () => {
    expect(() => validateLedgerEvent({ ...event("1", "a", "START"),
      id: "bad\nname" })).toThrow();
  });
});
describe("ledger transitions", () => {
  it("starts a task", () => {
    expect(replay([event("1", "a", "START")]).states.find(x =>
      x.taskId === "a")?.disposition).toBe("IN_PROGRESS");
  });
  it("completes a started task with evidence", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "evidence-1")]);
    expect(ledger.completed).toBe(1);
    expect(ledger.valid).toBe(true);
  });
  it("blocks completion without evidence", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later)]);
    expect(ledger.violations[0]?.code).toBe("MISSING_EVIDENCE");
  });
  it("allows completion without evidence when configured", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later)], true, {
        ...DEFAULT_LEDGER_POLICY, requireEvidenceForCompletion: false,
      });
    expect(ledger.completed).toBe(1);
  });
  it("rejects completion before start", () => {
    expect(replay([event("1", "a", "COMPLETE", at, "evidence")])
      .violations[0]?.code).toBe("INVALID_TRANSITION");
  });
  it("rejects duplicate start", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "START", later)]);
    expect(ledger.violations[0]?.code).toBe("INVALID_TRANSITION");
  });
  it("rejects duplicate event IDs", () => {
    const ledger = replay([event("1", "a", "START"),
      event("1", "a", "NOTE", later)]);
    expect(ledger.violations[0]?.code).toBe("DUPLICATE_EVENT");
  });
  it("rejects unknown task", () => {
    expect(replay([event("1", "missing", "START")])
      .violations[0]?.code).toBe("UNKNOWN_TASK");
  });
  it("rejects time regression", () => {
    const ledger = replay([event("1", "a", "START", later),
      event("2", "a", "NOTE", at)]);
    expect(ledger.violations[0]?.code).toBe("NONMONOTONIC_TIME");
  });
  it("blocks tasks", () => {
    const ledger = replay([event("1", "a", "BLOCK")]);
    expect(ledger.blocked).toBe(1);
  });
  it("unblocks tasks", () => {
    const ledger = replay([event("1", "a", "BLOCK"),
      event("2", "a", "UNBLOCK", later)]);
    expect(ledger.states.find(x => x.taskId === "a")?.disposition).toBe("READY");
  });
  it("rejects unblocking an unblocked task", () => {
    expect(replay([event("1", "a", "UNBLOCK")])
      .violations[0]?.code).toBe("INVALID_TRANSITION");
  });
  it("allows notes in planned state", () => {
    const ledger = replay([event("1", "a", "NOTE")]);
    expect(ledger.states.find(x => x.taskId === "a")?.noteCount).toBe(1);
  });
  it("deduplicates evidence references", () => {
    const ledger = replay([event("1", "a", "NOTE", at, "e1"),
      event("2", "a", "NOTE", later, "e1")]);
    expect(ledger.states.find(x => x.taskId === "a")?.evidenceReferences).toEqual(["e1"]);
  });
  it("rejects dependent start until prerequisite complete", () => {
    expect(replay([event("1", "b", "START")])
      .violations[0]?.code).toBe("DEPENDENCY_NOT_COMPLETE");
  });
  it("allows dependent start after prerequisite completes", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "e1"),
      event("3", "b", "START", latest)]);
    expect(ledger.states.find(x => x.taskId === "b")?.disposition).toBe("IN_PROGRESS");
  });
  it("can disable dependency enforcement", () => {
    const ledger = replay([event("1", "b", "START")], true, {
      ...DEFAULT_LEDGER_POLICY, enforceDependencies: false,
    });
    expect(ledger.active).toBe(1);
  });
  it("rejects cancellation by default", () => {
    expect(replay([event("1", "a", "CANCEL")])
      .violations[0]?.code).toBe("INVALID_TRANSITION");
  });
  it("allows cancellation under policy", () => {
    const ledger = replay([event("1", "a", "CANCEL")], true, {
      ...DEFAULT_LEDGER_POLICY, allowCancellation: true,
    });
    expect(ledger.states.find(x => x.taskId === "a")?.disposition).toBe("CANCELLED");
  });
  it("reopens completed tasks", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "e1"),
      event("3", "a", "REOPEN", latest)]);
    expect(ledger.states.find(x => x.taskId === "a")?.disposition).toBe("READY");
  });
  it("rejects reopen when policy forbids it", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "e1"),
      event("3", "a", "REOPEN", latest)], true, {
        ...DEFAULT_LEDGER_POLICY, allowReopen: false,
      });
    expect(ledger.violations[0]?.code).toBe("INVALID_TRANSITION");
  });
  it("rejects actions on partial source", () => {
    expect(replay([event("1", "a", "START")], false)
      .violations[0]?.code).toBe("INCOMPLETE_SOURCE");
  });
  it("allows notes on partial source", () => {
    expect(replay([event("1", "a", "NOTE")], false).valid).toBe(true);
  });
  it("allows partial source under explicit policy", () => {
    const ledger = replay([event("1", "a", "START")], false, {
      ...DEFAULT_LEDGER_POLICY, allowPartialSource: true,
    });
    expect(ledger.active).toBe(1);
  });
  it("enforces per-task event limit", () => {
    const ledger = replay([event("1", "a", "NOTE"),
      event("2", "a", "NOTE", later)], true, {
        ...DEFAULT_LEDGER_POLICY, maximumEventsPerTask: 1,
      });
    expect(ledger.violations[0]?.code).toBe("POLICY_LIMIT");
  });
  it("enforces global event limit", () => {
    expect(() => replay([event("1", "a", "NOTE"),
      event("2", "a", "NOTE", later)], true, {
        ...DEFAULT_LEDGER_POLICY, maximumEvents: 1,
      })).toThrow();
  });
  it("rejects duplicate backlog task IDs", () => {
    const item = task("a");
    expect(() => replayInvestigationLedger(backlog([item, item]), [])).toThrow();
  });
  it("preserves organization", () => {
    expect(replay([]).organizationId).toBe("org-a");
  });
  it("does not claim independent evidence verification", () => {
    expect(replay([]).warnings.some(x => x.includes("not cryptographically verified"))).toBe(true);
  });
  it("counts remaining minutes", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "e1")]);
    expect(ledger.remainingMinutes).toBe(30);
  });
  it("retains only accepted events", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "START", later)]);
    expect(ledger.events).toHaveLength(1);
  });
});
describe("ledger reports", () => {
  const completed = replay([event("1", "a", "START"),
    event("2", "a", "COMPLETE", later, "e1")]);
  it("counts completion ratio", () => {
    expect(investigationLedgerProgress(completed).completionRatio).toBe(0.5);
  });
  it("counts dispositions", () => {
    expect(investigationLedgerProgress(completed).byDisposition.DONE).toBe(1);
  });
  it("counts invalid events", () => {
    const invalid = replay([event("1", "a", "COMPLETE", at, "e1")]);
    expect(investigationLedgerProgress(invalid).invalidEvents).toBe(1);
  });
  it("exports JSON", () => {
    expect(JSON.parse(investigationLedgerJson(completed)).version).toBe(1);
  });
  it("exports CSV", () => {
    expect(investigationLedgerCsv(completed)).toContain("\r\n");
  });
  it("preserves last accepted event timestamp", () => {
    expect(completed.evaluatedAt).toBe(later);
  });
  it("reports no timestamp for empty ledger", () => {
    expect(replay([]).evaluatedAt).toBeNull();
  });
  it("reports zero-case ratio as one", () => {
    const empty = replayInvestigationLedger(backlog([]), []);
    expect(investigationLedgerProgress(empty).completionRatio).toBe(1);
  });
});
describe("ledger comparisons", () => {
  const before = replay([]);
  const after = replay([event("1", "a", "START"),
    event("2", "a", "COMPLETE", later, "e1")]);
  it("detects newly completed tasks", () => {
    expect(compareInvestigationLedgers(before, after).newlyCompleted).toEqual(["a"]);
  });
  it("detects reopened tasks", () => {
    const reopened = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "e1"),
      event("3", "a", "REOPEN", latest)]);
    expect(compareInvestigationLedgers(after, reopened).reopened).toEqual(["a"]);
  });
  it("detects newly blocked tasks", () => {
    expect(compareInvestigationLedgers(before,
      replay([event("1", "a", "BLOCK")])).newlyBlocked).toEqual(["a"]);
  });
  it("detects unblocked tasks", () => {
    const blocked = replay([event("1", "a", "BLOCK")]);
    const unblocked = replay([event("1", "a", "BLOCK"),
      event("2", "a", "UNBLOCK", later)]);
    expect(compareInvestigationLedgers(blocked, unblocked).unblocked).toEqual(["a"]);
  });
  it("rejects cross-tenant comparison", () => {
    expect(() => compareInvestigationLedgers(before,
      { ...after, organizationId: "org-b" })).toThrow();
  });
  it("treats partial source as uncertain", () => {
    const partial = replay([], false);
    expect(compareInvestigationLedgers(before, partial).uncertain).toHaveLength(2);
  });
  it("does not report unchanged tasks", () => {
    expect(compareInvestigationLedgers(before, before).changed).toEqual([]);
  });
  it("detects changed task sets", () => {
    const different = replayInvestigationLedger(backlog([task("c")]), []);
    expect(compareInvestigationLedgers(before, different).changed).toEqual([]);
  });
});
