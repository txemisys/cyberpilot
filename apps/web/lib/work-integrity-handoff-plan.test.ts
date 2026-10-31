import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import { DEFAULT_EFFORT_ASSUMPTIONS } from "./work-integrity-capacity";
import {
  DEFAULT_HANDOFF_PLAN_POLICY, validateHandoffPlanPolicy,
  createHandoffPlan, compareHandoffPlans, handoffPlanCsv, handoffPlanJson,
} from "./work-integrity-handoff-plan";
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
  parseCaseSnapshot({ organizationId: "org-1", source: "offline",
    capturedAt: at, complete, cases: rows });
const critical = row("critical", { severity: "critical" });
const regular = row("regular");
const reviewed = row("reviewed", { state: "ACKNOWLEDGED",
  reviewEventId: "event-1", reviewedRevision: 2,
  reviewRationale: "Investigated" });
const partial = row("partial", { completeCoverage: false });
const historical = row("historical", { historicalOnly: true });
const source = snapshot([critical, regular, reviewed, partial, historical]);
const staffing = {
  profiles: [{ analystId: "alice", availableMinutes: 1000,
    eligibleCodes: [] as string[],
    eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">,
    unavailable: false }],
  effort: DEFAULT_EFFORT_ASSUMPTIONS,
  excludeHistorical: true, includeReviewed: true,
  maximumCases: 100, maximumMinutes: 100000,
};
const requirements = [{
  id: "review", diagnosticCodes: [] as string[],
  mandatoryFields: ["reviewEventId", "reviewRationale"] as Array<"reviewEventId" | "reviewRationale">,
  requireCurrentRevision: true, requireCompleteCoverage: true,
  requireHumanReview: true,
}];
const build = (input = source, policy = DEFAULT_HANDOFF_PLAN_POLICY) =>
  createHandoffPlan(input, at, staffing, requirements, policy);
describe("handoff policy", () => {
  it("accepts default", () => {
    expect(validateHandoffPlanPolicy(DEFAULT_HANDOFF_PLAN_POLICY).maxPackets).toBe(1000);
  });
  it("rejects zero packets", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxPackets: 0 })).toThrow();
  });
  it("rejects excessive packets", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxPackets: 10001 })).toThrow();
  });
  it("rejects zero packet size", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxCasesPerPacket: 0 })).toThrow();
  });
  it("rejects excessive packet size", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxCasesPerPacket: 10001 })).toThrow();
  });
  it("rejects fractional packet size", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxCasesPerPacket: 1.5 })).toThrow();
  });
  it("rejects invalid grouping", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      groupBy: "OTHER" as never })).toThrow();
  });
  it("rejects nonboolean flags", () => {
    expect(() => validateHandoffPlanPolicy({ ...DEFAULT_HANDOFF_PLAN_POLICY,
      includeReviewed: "yes" as never })).toThrow();
  });
});
describe("handoff generation", () => {
  const plan = build();
  it("preserves organization", () => expect(plan.organizationId).toBe("org-1"));
  it("preserves capture time", () => expect(plan.capturedAt).toBe(at));
  it("excludes historical cases", () => expect(plan.totalCases).toBe(4));
  it("counts omitted cases", () => expect(plan.omittedCases).toBe(1));
  it("includes historical cases when requested", () => {
    expect(build(source, { ...DEFAULT_HANDOFF_PLAN_POLICY,
      includeHistorical: true }).totalCases).toBe(5);
  });
  it("excludes reviewed cases when requested", () => {
    expect(build(source, { ...DEFAULT_HANDOFF_PLAN_POLICY,
      includeReviewed: false }).totalCases).toBe(3);
  });
  it("limits packet size", () => {
    expect(build(source, { ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxCasesPerPacket: 1 }).packets.every(packet => packet.cases.length <= 1)).toBe(true);
  });
  it("rejects packet limit overflow", () => {
    expect(() => build(source, { ...DEFAULT_HANDOFF_PLAN_POLICY,
      maxCasesPerPacket: 1, maxPackets: 1 })).toThrow();
  });
  it("groups by work item", () => {
    const result = build(source, { ...DEFAULT_HANDOFF_PLAN_POLICY, groupBy: "WORK_ITEM" });
    expect(result.packets.some(packet => packet.groupKey === "critical")).toBe(true);
  });
  it("groups by diagnostic code", () => {
    const result = build(source, { ...DEFAULT_HANDOFF_PLAN_POLICY, groupBy: "DIAGNOSTIC" });
    expect(result.packets.every(packet => packet.groupKey === "DONE_WITHOUT_COMPLETION")).toBe(true);
  });
  it("reports evidence gaps", () => expect(plan.evidenceBlockedCases).toBeGreaterThan(0));
  it("reports evidence-ready reviewed case", () => {
    const item = plan.packets.flatMap(packet => packet.cases)
      .find(item => item.caseKey === reviewed.key);
    expect(item?.evidenceReady).toBe(true);
  });
  it("records analyst recommendation", () => {
    expect(plan.packets.flatMap(packet => packet.cases).some(item =>
      item.assignedAnalystId === "alice")).toBe(true);
  });
  it("records SLA phases", () => {
    expect(plan.packets.flatMap(packet => packet.cases).every(item =>
      item.slaPhase.length > 0)).toBe(true);
  });
  it("reports incomplete linked evidence", () => {
    expect(plan.packets.some(packet => !packet.complete)).toBe(true);
  });
  it("reports partial source under permissive policy", () => {
    const result = build(snapshot([regular], false), {
      ...DEFAULT_HANDOFF_PLAN_POLICY, requireCompleteCapture: false,
    });
    expect(result.complete).toBe(false);
  });
  it("rejects partial source under strict policy", () => {
    expect(() => build(snapshot([regular], false))).toThrow();
  });
  it("does not claim real assignments", () => {
    expect(plan.warnings.some(message => message.includes("do not create real assignments"))).toBe(true);
  });
  it("exports JSON", () => expect(JSON.parse(handoffPlanJson(plan)).version).toBe(1));
  it("exports CSV", () => expect(handoffPlanCsv(plan)).toContain("\r\n"));
  it("neutralizes spreadsheet formulas", () => {
    const injected = row("=HYPERLINK");
    expect(handoffPlanCsv(build(snapshot([injected])))).toContain("'=HYPERLINK");
  });
});
describe("handoff comparisons", () => {
  const old = build(snapshot([regular]));
  const newer = build(snapshot([regular, critical]));
  it("detects added case", () => {
    expect(compareHandoffPlans(old, newer).newCaseKeys).toContain(critical.key);
  });
  it("detects removed case", () => {
    expect(compareHandoffPlans(newer, old).removedCaseKeys).toContain(critical.key);
  });
  it("rejects cross-tenant comparison", () => {
    expect(() => compareHandoffPlans(old, { ...newer, organizationId: "other" })).toThrow();
  });
  it("marks partial comparison uncertain", () => {
    const partialPlan = build(snapshot([regular], false), {
      ...DEFAULT_HANDOFF_PLAN_POLICY, requireCompleteCapture: false,
    });
    expect(compareHandoffPlans(newer, partialPlan).uncertainCaseKeys).toContain(critical.key);
  });
  it("recognizes unchanged assignment", () => {
    expect(compareHandoffPlans(old, old).reassignedCaseKeys).toEqual([]);
  });
  it("recognizes improved evidence", () => {
    const after = build(snapshot([row("regular", {
      state: "ACKNOWLEDGED", reviewEventId: "audit-1",
      reviewedRevision: 2, reviewRationale: "Checked",
    })]));
    expect(compareHandoffPlans(old, after).evidenceImprovedCaseKeys).toContain(regular.key);
  });
  it("recognizes degraded evidence", () => {
    const before = build(snapshot([row("regular", {
      state: "ACKNOWLEDGED", reviewEventId: "audit-1",
      reviewedRevision: 2, reviewRationale: "Checked",
    })]));
    expect(compareHandoffPlans(before, old).evidenceDegradedCaseKeys).toContain(regular.key);
  });
  it("recognizes assignment changes", () => {
    const altered = structuredClone(old);
    altered.packets[0]!.cases[0]!.assignedAnalystId = "bob";
    expect(compareHandoffPlans(old, altered).reassignedCaseKeys).toHaveLength(1);
  });
});
