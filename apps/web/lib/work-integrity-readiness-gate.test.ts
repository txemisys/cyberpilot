import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import { DEFAULT_EFFORT_ASSUMPTIONS } from "./work-integrity-capacity";
import {
  DEFAULT_READINESS_GATE, validateReadinessGatePolicy, evaluateReadinessGate,
  compareReadinessGates, readinessGateCsv, readinessGateJson,
} from "./work-integrity-readiness-gate";
const row = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 1, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const anchor = "2026-10-31T10:00:00.000Z";
const snapshot = (rows: CaseRow[], complete = true) =>
  parseCaseSnapshot({ organizationId: "org-a", source: "offline",
    capturedAt: anchor, complete, cases: rows });
const reviewed = row("reviewed", { state: "ACKNOWLEDGED",
  reviewEventId: "event-1", reviewedRevision: 1,
  reviewRationale: "Investigated", reviewReference: "case-1",
  reviewedAt: "2026-10-31T10:00:00.000Z" });
const stale = row("stale", { state: "STALE", reviewEventId: "event-2",
  reviewedRevision: 0 });
const urgent = row("urgent", { severity: "critical" });
const partial = row("partial", { completeCoverage: false });
const source = snapshot([reviewed, stale, urgent, partial]);
const capacity = {
  profiles: [{ analystId: "alice", availableMinutes: 1000,
    eligibleCodes: [] as string[],
    eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">,
    unavailable: false }],
  effort: DEFAULT_EFFORT_ASSUMPTIONS, excludeHistorical: true,
  includeReviewed: true, maximumCases: 100, maximumMinutes: 100000,
};
const evidence = [{
  id: "review", diagnosticCodes: [] as string[],
  mandatoryFields: ["reviewEventId", "reviewRationale"] as Array<"reviewEventId" | "reviewRationale">,
  requireCurrentRevision: true, requireCompleteCoverage: true,
  requireHumanReview: true,
}];
const assess = (rows = source, policy = DEFAULT_READINESS_GATE,
  assessedAt = "2026-10-31T10:00:00.000Z") =>
  evaluateReadinessGate(rows, assessedAt, policy, capacity, evidence);
describe("readiness gate policy validation", () => {
  it("accepts default policy", () => {
    expect(validateReadinessGatePolicy(DEFAULT_READINESS_GATE).thresholds).toHaveLength(8);
  });
  it("rejects duplicate criterion", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE,
      thresholds: [DEFAULT_READINESS_GATE.thresholds[0]!,
        DEFAULT_READINESS_GATE.thresholds[0]!],
    })).toThrow();
  });
  it("rejects unknown criterion", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE,
      thresholds: [{ criterion: "UNKNOWN" as never, required: true, minimumRatio: 1 }],
    })).toThrow();
  });
  it("rejects negative threshold", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE,
      thresholds: [{ criterion: "COMPLETE_SNAPSHOT", required: true, minimumRatio: -1 }],
    })).toThrow();
  });
  it("rejects threshold over one", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE,
      thresholds: [{ criterion: "COMPLETE_SNAPSHOT", required: true, minimumRatio: 1.1 }],
    })).toThrow();
  });
  it("rejects invalid required flag", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE,
      thresholds: [{ criterion: "COMPLETE_SNAPSHOT", required: 1 as never, minimumRatio: 1 }],
    })).toThrow();
  });
  it("rejects zero maximum cases", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE, maxCases: 0,
    })).toThrow();
  });
  it("rejects invalid mode flag", () => {
    expect(() => validateReadinessGatePolicy({
      ...DEFAULT_READINESS_GATE, requireAllCriteria: "yes" as never,
    })).toThrow();
  });
});
describe("readiness gate evaluation", () => {
  const report = assess();
  it("preserves tenant", () => expect(report.organizationId).toBe("org-a"));
  it("evaluates eight criteria", () => expect(report.findings).toHaveLength(8));
  it("fails on incomplete linked coverage", () => {
    expect(report.blocking.some(item => item.criterion === "COMPLETE_LINKED_COVERAGE")).toBe(true);
  });
  it("fails on stale reviews", () => {
    expect(report.blocking.some(item => item.criterion === "NO_STALE_REVIEWS")).toBe(true);
  });
  it("fails on unreviewed critical case", () => {
    expect(report.blocking.some(item => item.criterion === "NO_CRITICAL_UNREVIEWED")).toBe(true);
  });
  it("fails on missing evidence", () => {
    expect(report.blocking.some(item => item.criterion === "EVIDENCE_READY")).toBe(true);
  });
  it("passes complete snapshot criterion", () => {
    expect(report.findings.find(item => item.criterion === "COMPLETE_SNAPSHOT")?.passed).toBe(true);
  });
  it("fails overall when mandatory criteria fail", () => expect(report.passed).toBe(false));
  it("reports advisory failures separately", () => {
    const policy = { ...DEFAULT_READINESS_GATE, thresholds: [{
      criterion: "EVIDENCE_READY" as const, required: false, minimumRatio: 1,
    }] };
    expect(assess(source, policy).advisory).toHaveLength(1);
  });
  it("supports ratio thresholds", () => {
    const policy = { ...DEFAULT_READINESS_GATE, thresholds: [{
      criterion: "COMPLETE_LINKED_COVERAGE" as const,
      required: true, minimumRatio: 0.75,
    }] };
    expect(assess(source, policy).passed).toBe(true);
  });
  it("supports any-of mode", () => {
    const policy = { ...DEFAULT_READINESS_GATE, requireAllCriteria: false };
    expect(assess(source, policy).passed).toBe(true);
  });
  it("marks incomplete snapshot", () => {
    const report = assess(snapshot([reviewed], false));
    expect(report.findings.find(item => item.criterion === "COMPLETE_SNAPSHOT")?.passed).toBe(false);
  });
  it("passes ready reviewed case under focused criteria", () => {
    const policy = { ...DEFAULT_READINESS_GATE, thresholds: [{
      criterion: "EVIDENCE_READY" as const, required: true, minimumRatio: 1,
    }] };
    expect(assess(snapshot([reviewed]), policy).passed).toBe(true);
  });
  it("counts capacity coverage", () => {
    const finding = report.findings.find(item => item.criterion === "CAPACITY_COVERED");
    expect(finding?.denominator).toBe(4);
  });
  it("identifies escalated SLA after threshold", () => {
    const late = assess(snapshot([urgent]), DEFAULT_READINESS_GATE,
      "2026-10-31T12:00:00.000Z");
    expect(late.findings.find(item => item.criterion === "NO_ESCALATED_SLA")?.passed).toBe(false);
  });
  it("rejects excessive cases", () => {
    expect(() => assess(source, { ...DEFAULT_READINESS_GATE, maxCases: 1 })).toThrow();
  });
  it("does not claim security authorization", () => {
    expect(report.warnings.some(item => item.includes("not a security authorization"))).toBe(true);
  });
  it("exports JSON", () => {
    expect(JSON.parse(readinessGateJson(report)).version).toBe(1);
  });
  it("exports CSV", () => expect(readinessGateCsv(report)).toContain("\r\n"));
});
describe("readiness gate comparisons", () => {
  const before = assess(snapshot([urgent]));
  const after = assess(snapshot([reviewed]));
  it("rejects cross-tenant comparison", () => {
    expect(() => compareReadinessGates(before, { ...after, organizationId: "other" })).toThrow();
  });
  it("detects improved evidence readiness", () => {
    expect(compareReadinessGates(before, after).improved).toContain("EVIDENCE_READY");
  });
  it("detects improved critical review coverage", () => {
    const old = assess(snapshot([urgent]));
    const newCase = row("urgent", { severity: "critical", state: "ACKNOWLEDGED",
      reviewEventId: "audit-1", reviewedRevision: 1,
      reviewRationale: "Reviewed" });
    const newer = assess(snapshot([newCase]));
    expect(compareReadinessGates(old, newer).improved).toContain("NO_CRITICAL_UNREVIEWED");
  });
  it("detects degradation", () => {
    expect(compareReadinessGates(after, before).degraded).toContain("EVIDENCE_READY");
  });
  it("recognizes unchanged criteria", () => {
    expect(compareReadinessGates(before, before).unchanged).toContain("COMPLETE_SNAPSHOT");
  });
  it("marks partial capture comparisons uncertain", () => {
    const partial = assess(snapshot([reviewed], false));
    expect(compareReadinessGates(before, partial).unknown).toContain("EVIDENCE_READY");
  });
  it("reports pass state before and after", () => {
    const comparison = compareReadinessGates(before, after);
    expect(comparison.passedBefore).toBe(false);
  });
});
