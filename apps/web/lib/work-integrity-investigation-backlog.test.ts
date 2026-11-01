import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import { DEFAULT_EFFORT_ASSUMPTIONS } from "./work-integrity-capacity";
import {
  DEFAULT_INVESTIGATION_POLICY, validateInvestigationPolicy,
  createInvestigationBacklog, scheduleInvestigationBacklog,
  compareInvestigationBacklogs, investigationBacklogCsv, investigationBacklogJson,
  type InvestigationBacklog,
} from "./work-integrity-investigation-backlog";
const row = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 2, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const at = "2026-10-31T10:00:00.000Z";
const snapshot = (rows: CaseRow[], complete = true) =>
  parseCaseSnapshot({ organizationId: "org-a", source: "offline",
    capturedAt: at, complete, cases: rows });
const urgent = row("urgent", { severity: "critical" });
const reviewed = row("reviewed", { state: "ACKNOWLEDGED",
  reviewEventId: "audit-1", reviewedRevision: 2,
  reviewRationale: "Inspected" });
const stale = row("stale", { state: "STALE", reviewEventId: "audit-2",
  reviewedRevision: 1 });
const partial = row("partial", { completeCoverage: false });
const historical = row("historical", { historicalOnly: true });
const source = snapshot([urgent, reviewed, stale, partial, historical]);
const capacity = {
  profiles: [{ analystId: "alice", availableMinutes: 1000,
    eligibleCodes: [] as string[],
    eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">,
    unavailable: false }],
  effort: DEFAULT_EFFORT_ASSUMPTIONS,
  excludeHistorical: true, includeReviewed: true,
  maximumCases: 100, maximumMinutes: 100000,
};
const evidence = [{
  id: "review", diagnosticCodes: [] as string[],
  mandatoryFields: ["reviewEventId", "reviewRationale"] as Array<"reviewEventId" | "reviewRationale">,
  requireCurrentRevision: true, requireCompleteCoverage: true,
  requireHumanReview: true,
}];
const build = (input = source, policy = DEFAULT_INVESTIGATION_POLICY,
  assessedAt = at) => createInvestigationBacklog(input, assessedAt,
  capacity, evidence, policy);
describe("investigation policy", () => {
  it("accepts default", () => {
    expect(validateInvestigationPolicy(DEFAULT_INVESTIGATION_POLICY).maxTasks).toBe(100000);
  });
  it("rejects zero effort", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY,
      minutesByKind: { ...DEFAULT_INVESTIGATION_POLICY.minutesByKind, REVIEW: 0 },
    })).toThrow();
  });
  it("rejects fractional effort", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY,
      minutesByKind: { ...DEFAULT_INVESTIGATION_POLICY.minutesByKind, VERIFY: 1.5 },
    })).toThrow();
  });
  it("rejects negative effort", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY,
      minutesByKind: { ...DEFAULT_INVESTIGATION_POLICY.minutesByKind, RECOLLECT: -1 },
    })).toThrow();
  });
  it("rejects zero maximum tasks", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY, maxTasks: 0,
    })).toThrow();
  });
  it("rejects excessive maximum tasks", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY, maxTasks: 100001,
    })).toThrow();
  });
  it("rejects nonboolean historical flag", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY, includeHistorical: 1 as never,
    })).toThrow();
  });
  it("rejects nonboolean verification flag", () => {
    expect(() => validateInvestigationPolicy({
      ...DEFAULT_INVESTIGATION_POLICY, alwaysVerify: "yes" as never,
    })).toThrow();
  });
});
describe("investigation backlog", () => {
  const backlog = build();
  it("preserves organization", () => expect(backlog.organizationId).toBe("org-a"));
  it("preserves capture time", () => expect(backlog.capturedAt).toBe(at));
  it("contains review tasks", () => expect(backlog.byKind.REVIEW).toBeGreaterThan(0));
  it("contains reassessment tasks", () => expect(backlog.byKind.REASSESS).toBeGreaterThan(0));
  it("contains recollection tasks", () => expect(backlog.byKind.RECOLLECT).toBeGreaterThan(0));
  it("contains evidence completion tasks", () => expect(backlog.byKind.COMPLETE_EVIDENCE).toBeGreaterThan(0));
  it("contains independent verification tasks", () => expect(backlog.byKind.VERIFY).toBe(4));
  it("excludes historical cases by default", () => {
    expect(backlog.tasks.every(task => task.caseKey !== historical.key)).toBe(true);
  });
  it("includes historical when requested", () => {
    expect(build(source, { ...DEFAULT_INVESTIGATION_POLICY,
      includeHistorical: true }).tasks.some(task => task.caseKey === historical.key)).toBe(true);
  });
  it("excludes reviewed cases when requested", () => {
    expect(build(source, { ...DEFAULT_INVESTIGATION_POLICY,
      includeReviewed: false }).tasks.some(task => task.caseKey === reviewed.key)).toBe(false);
  });
  it("omits verification when disabled", () => {
    expect(build(source, { ...DEFAULT_INVESTIGATION_POLICY,
      alwaysVerify: false }).byKind.VERIFY).toBe(0);
  });
  it("limits generated tasks", () => {
    expect(() => build(source, { ...DEFAULT_INVESTIGATION_POLICY,
      maxTasks: 1 })).toThrow();
  });
  it("computes total effort", () => {
    expect(backlog.estimatedMinutes).toBe(backlog.tasks.reduce((sum, task) =>
      sum + task.estimatedMinutes, 0));
  });
  it("creates distinct task IDs", () => {
    expect(new Set(backlog.tasks.map(task => task.id)).size).toBe(backlog.tasks.length);
  });
  it("does not create assignments", () => {
    expect(backlog.warnings.some(message => message.includes("none are executed"))).toBe(true);
  });
  it("reports partial source", () => {
    expect(build(snapshot([urgent], false)).complete).toBe(false);
  });
  it("adds recollection for incomplete source", () => {
    expect(build(snapshot([urgent], false)).byKind.RECOLLECT).toBe(1);
  });
  it("adds escalation after SLA threshold", () => {
    expect(build(snapshot([urgent]), DEFAULT_INVESTIGATION_POLICY,
      "2026-10-31T12:00:00.000Z").byKind.ESCALATE).toBe(1);
  });
  it("records prerequisite dependencies", () => {
    expect(backlog.tasks.some(task => task.dependsOn.length > 0)).toBe(true);
  });
  it("exports JSON", () => expect(JSON.parse(investigationBacklogJson(backlog)).version).toBe(1));
  it("exports CSV", () => expect(investigationBacklogCsv(backlog)).toContain("\r\n"));
  it("neutralizes formula injection", () => {
    const injection = row("=HYPERLINK");
    expect(investigationBacklogCsv(build(snapshot([injection])))).toContain("'=HYPERLINK");
  });
});
describe("dependency scheduling", () => {
  const backlog = build(snapshot([urgent]));
  it("generates execution waves", () => {
    expect(scheduleInvestigationBacklog(backlog).waves.length).toBeGreaterThan(1);
  });
  it("schedules every task once", () => {
    const result = scheduleInvestigationBacklog(backlog);
    expect(result.waves.flatMap(wave => wave.taskIds)).toHaveLength(backlog.tasks.length);
  });
  it("schedules prerequisites before dependents", () => {
    const schedule = scheduleInvestigationBacklog(backlog);
    const waveById = new Map(schedule.waves.flatMap(wave =>
      wave.taskIds.map(id => [id, wave.index] as const)));
    for (const task of backlog.tasks)
      for (const dependency of task.dependsOn)
        expect(waveById.get(dependency)).toBeLessThan(waveById.get(task.id)!);
  });
  it("rejects duplicate task IDs", () => {
    const duplicate: InvestigationBacklog = {
      ...backlog, tasks: [backlog.tasks[0]!, backlog.tasks[0]!],
    };
    expect(() => scheduleInvestigationBacklog(duplicate)).toThrow();
  });
  it("detects unresolved dependency", () => {
    const modified: InvestigationBacklog = {
      ...backlog, tasks: backlog.tasks.map((task, index) =>
        index === 0 ? { ...task, dependsOn: ["missing"] } : task),
    };
    expect(scheduleInvestigationBacklog(modified).unresolvedDependencies).toContain("missing");
  });
  it("detects cyclic dependencies", () => {
    const tasks = backlog.tasks.slice(0, 2).map(task => ({ ...task }));
    tasks[0]!.dependsOn = [tasks[1]!.id];
    tasks[1]!.dependsOn = [tasks[0]!.id];
    const cyclic = scheduleInvestigationBacklog({ ...backlog, tasks });
    expect(cyclic.cyclicTaskIds).toHaveLength(2);
    expect(cyclic.executable).toBe(false);
  });
  it("marks partial source nonexecutable", () => {
    const partialBacklog = build(snapshot([urgent], false));
    expect(scheduleInvestigationBacklog(partialBacklog).executable).toBe(false);
  });
});
describe("backlog comparisons", () => {
  const before = build(snapshot([urgent]));
  const after = build(snapshot([urgent, reviewed]));
  it("detects newly introduced tasks", () => {
    expect(compareInvestigationBacklogs(before, after).added.length).toBeGreaterThan(0);
  });
  it("detects removed tasks", () => {
    expect(compareInvestigationBacklogs(after, before).removed.length).toBeGreaterThan(0);
  });
  it("rejects cross-tenant comparisons", () => {
    expect(() => compareInvestigationBacklogs(before, {
      ...after, organizationId: "other",
    })).toThrow();
  });
  it("recognizes unchanged tasks", () => {
    const diff = compareInvestigationBacklogs(before, before);
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
    expect(diff.reassigned).toEqual([]);
  });
  it("recognizes changed assignments", () => {
    const altered: InvestigationBacklog = {
      ...before, tasks: before.tasks.map(task => ({
        ...task, assignedAnalystId: "different",
      })),
    };
    expect(compareInvestigationBacklogs(before, altered).reassigned.length).toBeGreaterThan(0);
  });
  it("recognizes changed dependencies", () => {
    const altered: InvestigationBacklog = {
      ...before, tasks: before.tasks.map((task, index) => index === 0
        ? { ...task, dependsOn: ["another"] } : task),
    };
    expect(compareInvestigationBacklogs(before, altered).changedDependencies).toHaveLength(1);
  });
  it("marks partial source differences uncertain", () => {
    const partial = build(snapshot([urgent], false));
    expect(compareInvestigationBacklogs(after, partial).uncertain.length).toBeGreaterThan(0);
  });
});
