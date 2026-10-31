import { describe, expect, it } from "vitest";
import type { InvestigationBacklog, InvestigationTask } from "./work-integrity-investigation-backlog";
import {
  DEFAULT_LEDGER_POLICY, replayInvestigationLedger,
  type LedgerEvent,
} from "./work-integrity-investigation-ledger";
import {
  reconcileInvestigationLedger, buildInvestigationLedgerTimeline,
  ledgerActorActivity, ledgerReconciliationCsv, ledgerTimelineJson,
} from "./work-integrity-ledger-reconciliation";
const at = "2026-10-31T10:00:00.000Z";
const later = "2026-10-31T10:01:00.000Z";
const latest = "2026-10-31T10:02:00.000Z";
const task = (id: string, dependencies: string[] = []): InvestigationTask => ({
  id, caseKey: "case-" + id, workItemId: "work-" + id,
  kind: "REVIEW", priority: "P1", dependsOn: dependencies,
  estimatedMinutes: 20, assignedAnalystId: "alice",
  rationale: "Review evidence", coverageComplete: true,
});
const backlog = (tasks: InvestigationTask[] = [task("a"), task("b", ["a"])],
  complete = true): InvestigationBacklog => ({
  version: 1, organizationId: "org-a", capturedAt: at,
  assessedAt: at, complete, tasks,
  byKind: { RECOLLECT: 0, REASSESS: 0, REVIEW: tasks.length,
    COMPLETE_EVIDENCE: 0, ALLOCATE_CAPACITY: 0, ESCALATE: 0, VERIFY: 0 },
  estimatedMinutes: tasks.length * 20, unassignedTasks: 0, warnings: [],
});
const event = (id: string, taskId: string, kind: LedgerEvent["kind"],
  time = at, evidenceReference: string | null = null): LedgerEvent => ({
  id, taskId, kind, at: time, actorId: "reviewer-1",
  rationale: "Reviewed source", evidenceReference,
});
const source = backlog();
const replay = (events: LedgerEvent[] = []) =>
  replayInvestigationLedger(source, events);
describe("ledger reconciliation", () => {
  it("accepts an untouched complete plan", () => {
    expect(reconcileInvestigationLedger(source, replay()).blockingCount).toBe(0);
  });
  it("preserves organization", () => {
    expect(reconcileInvestigationLedger(source, replay()).organizationId).toBe("org-a");
  });
  it("rejects different organization", () => {
    expect(() => reconcileInvestigationLedger(source,
      { ...replay(), organizationId: "other" })).toThrow();
  });
  it("rejects different capture", () => {
    expect(() => reconcileInvestigationLedger(source,
      { ...replay(), capturedAt: later })).toThrow();
  });
  it("detects missing state", () => {
    const altered = replay();
    altered.states = altered.states.filter(item => item.taskId !== "a");
    expect(reconcileInvestigationLedger(source, altered).findings.some(item =>
      item.code === "MISSING_STATE")).toBe(true);
  });
  it("detects unplanned state", () => {
    const altered = replay();
    altered.states.push({ ...altered.states[0]!, taskId: "unknown" });
    expect(reconcileInvestigationLedger(source, altered).findings.some(item =>
      item.code === "UNPLANNED_STATE")).toBe(true);
  });
  it("detects incomplete task coverage", () => {
    const partial = backlog([task("a")]);
    partial.tasks[0]!.coverageComplete = false;
    const ledger = replayInvestigationLedger(partial, []);
    expect(reconcileInvestigationLedger(partial, ledger).findings.some(item =>
      item.code === "INCOMPLETE_COVERAGE")).toBe(true);
  });
  it("detects missing prerequisite task", () => {
    const broken = backlog([task("a", ["unknown"])]);
    const ledger = replayInvestigationLedger(broken, []);
    expect(reconcileInvestigationLedger(broken, ledger).findings.some(item =>
      item.code === "MISSING_DEPENDENCY")).toBe(true);
  });
  it("flags unassigned activity as advisory", () => {
    const unassigned = backlog([{
      ...task("a"), assignedAnalystId: null,
    }]);
    const ledger = replayInvestigationLedger(unassigned, [event("1", "a", "NOTE")]);
    expect(reconcileInvestigationLedger(unassigned, ledger).advisoryCount).toBe(1);
  });
  it("detects missing completion evidence", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later)],);
    const report = reconcileInvestigationLedger(source, ledger);
    expect(report.findings.some(item => item.code === "EVIDENCE_NOT_RECORDED")).toBe(false);
  });
  it("blocks incomplete source verification", () => {
    const partial = backlog(undefined, false);
    const ledger = replayInvestigationLedger(partial, []);
    expect(reconcileInvestigationLedger(partial, ledger)
      .readyForIndependentVerification).toBe(false);
  });
  it("exports CSV", () => {
    expect(ledgerReconciliationCsv(reconcileInvestigationLedger(source, replay())))
      .toContain("\r\n");
  });
  it("warns about unverifiable claims", () => {
    expect(reconcileInvestigationLedger(source, replay()).warnings.some(item =>
      item.includes("not actual completion"))).toBe(true);
  });
});
describe("ledger timeline", () => {
  const events = [event("1", "a", "START"),
    event("2", "a", "COMPLETE", later, "evidence-1"),
    event("3", "b", "START", latest)];
  const timeline = buildInvestigationLedgerTimeline(source, events, DEFAULT_LEDGER_POLICY);
  it("includes initial state", () => expect(timeline.points).toHaveLength(4));
  it("preserves tenant", () => expect(timeline.organizationId).toBe("org-a"));
  it("counts accepted events", () => expect(timeline.totalAccepted).toBe(3));
  it("counts completion", () => expect(timeline.points.at(-1)?.completed).toBe(1));
  it("counts active tasks", () => expect(timeline.points.at(-1)?.active).toBe(1));
  it("reduces remaining minutes", () => expect(timeline.points.at(-1)?.remainingMinutes).toBe(20));
  it("counts invalid events", () => {
    const invalid = buildInvestigationLedgerTimeline(source,
      [event("1", "b", "START")], DEFAULT_LEDGER_POLICY);
    expect(invalid.totalRejected).toBe(1);
  });
  it("rejects zero limit", () => {
    expect(() => buildInvestigationLedgerTimeline(source, [], DEFAULT_LEDGER_POLICY, 0)).toThrow();
  });
  it("rejects excessive limit", () => {
    expect(() => buildInvestigationLedgerTimeline(source, [], DEFAULT_LEDGER_POLICY, 1001)).toThrow();
  });
  it("rejects overlong history", () => {
    expect(() => buildInvestigationLedgerTimeline(source, events,
      DEFAULT_LEDGER_POLICY, 2)).toThrow();
  });
  it("exports JSON", () => {
    expect(JSON.parse(ledgerTimelineJson(timeline)).totalAccepted).toBe(3);
  });
});
describe("actor activity", () => {
  it("reports empty activity", () => expect(ledgerActorActivity(replay())).toEqual([]));
  it("counts events", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "NOTE", later)]);
    expect(ledgerActorActivity(ledger)[0]?.eventCount).toBe(2);
  });
  it("counts distinct tasks", () => {
    const ledger = replay([event("1", "a", "NOTE"),
      event("2", "b", "NOTE", later)]);
    expect(ledgerActorActivity(ledger)[0]?.distinctTasks).toBe(2);
  });
  it("counts completion events", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "COMPLETE", later, "evidence")]);
    expect(ledgerActorActivity(ledger)[0]?.completedEvents).toBe(1);
  });
  it("counts blocking events", () => {
    const ledger = replay([event("1", "a", "BLOCK")]);
    expect(ledgerActorActivity(ledger)[0]?.blockedEvents).toBe(1);
  });
  it("reports first and last activity", () => {
    const ledger = replay([event("1", "a", "START"),
      event("2", "a", "NOTE", later)]);
    expect(ledgerActorActivity(ledger)[0]?.firstAt).toBe(at);
    expect(ledgerActorActivity(ledger)[0]?.lastAt).toBe(later);
  });
});
