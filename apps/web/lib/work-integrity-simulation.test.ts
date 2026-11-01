import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import { DEFAULT_EFFORT_ASSUMPTIONS } from "./work-integrity-capacity";
import {
  validateSimulationPolicy, proposeInterventions, simulateInterventions,
  compareSimulationPortfolio, buildOperationalPulse, operationalPulseCsv,
  operationalPulseJson,
} from "./work-integrity-simulation";
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
const anchor = "2026-10-31T10:00:00.000Z";
const snapshot = (rows: CaseRow[], complete = true) =>
  parseCaseSnapshot({ organizationId: "org-1", source: "offline",
    capturedAt: anchor, complete, cases: rows });
const urgent = row("urgent", { severity: "critical" });
const stale = row("stale", { state: "STALE", reviewEventId: "audit-1",
  reviewedRevision: 1 });
const partial = row("partial", { completeCoverage: false });
const historical = row("historical", { historicalOnly: true });
const regular = row("regular");
const source = snapshot([urgent, stale, partial, historical, regular]);
const effort = { P0: 60, P1: 45, P2: 30, P3: 20, P4: 10 };
const interventions = proposeInterventions(source, effort);
const policy = {
  interventions, budgetMinutes: 120, maximumInterventions: 5,
  allowIncompleteCoverage: false, prioritiseUrgent: true,
};
const capacity = {
  profiles: [{ analystId: "alice", availableMinutes: 240,
    eligibleCodes: [] as string[],
    eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">,
    unavailable: false }],
  effort: DEFAULT_EFFORT_ASSUMPTIONS, excludeHistorical: true,
  includeReviewed: true, maximumCases: 100, maximumMinutes: 100000,
};
describe("simulation policy validation", () => {
  it("accepts valid policy", () => expect(validateSimulationPolicy(policy).interventions).toHaveLength(4));
  it("rejects negative budget", () => expect(() => validateSimulationPolicy({
    ...policy, budgetMinutes: -1,
  })).toThrow());
  it("rejects noninteger budget", () => expect(() => validateSimulationPolicy({
    ...policy, budgetMinutes: 1.5,
  })).toThrow());
  it("rejects invalid intervention bound", () => expect(() => validateSimulationPolicy({
    ...policy, maximumInterventions: 0,
  })).toThrow());
  it("rejects duplicate intervention ID", () => expect(() => validateSimulationPolicy({
    ...policy, interventions: [interventions[0]!, interventions[0]!],
  })).toThrow());
  it("rejects unknown intervention type", () => expect(() => validateSimulationPolicy({
    ...policy, interventions: [{ ...interventions[0]!, kind: "DELETE" as never }],
  })).toThrow());
  it("rejects duplicate case keys within an intervention", () => {
    const first = interventions[0]!;
    expect(() => validateSimulationPolicy({
      ...policy, interventions: [{ ...first, caseKeys: [first.caseKeys[0]!, first.caseKeys[0]!] }],
    })).toThrow();
  });
  it("rejects empty case keys", () => expect(() => validateSimulationPolicy({
    ...policy, interventions: [{ ...interventions[0]!, caseKeys: [] }],
  })).toThrow());
  it("rejects negative benefit", () => expect(() => validateSimulationPolicy({
    ...policy, interventions: [{ ...interventions[0]!, expectedBenefit: -1 }],
  })).toThrow());
  it("rejects invalid coverage flag", () => expect(() => validateSimulationPolicy({
    ...policy, interventions: [{ ...interventions[0]!, requiresCompleteCoverage: 1 as never }],
  })).toThrow());
  it("rejects invalid policy flag", () => expect(() => validateSimulationPolicy({
    ...policy, prioritiseUrgent: "yes" as never,
  })).toThrow());
});
describe("intervention proposals", () => {
  it("excludes historical cases", () => expect(interventions).toHaveLength(4));
  it("proposes recollection for partial coverage", () => {
    expect(interventions.find(item => item.caseKeys.includes(partial.key))?.kind).toBe("RECOLLECT");
  });
  it("proposes reassessment for stale review", () => {
    expect(interventions.find(item => item.caseKeys.includes(stale.key))?.kind).toBe("REASSESS");
  });
  it("proposes review for unreviewed case", () => {
    expect(interventions.find(item => item.caseKeys.includes(urgent.key))?.kind).toBe("REVIEW");
  });
  it("assigns benefit from priority", () => {
    expect(interventions.find(item => item.caseKeys.includes(urgent.key))?.expectedBenefit).toBe(5);
  });
  it("rejects zero effort", () => {
    expect(() => proposeInterventions(source, { ...effort, P0: 0 })).toThrow();
  });
  it("rejects noninteger effort", () => {
    expect(() => proposeInterventions(source, { ...effort, P1: 1.5 })).toThrow();
  });
});
describe("budgeted intervention simulation", () => {
  const result = simulateInterventions(source, policy);
  it("preserves tenant scope", () => expect(result.organizationId).toBe("org-1"));
  it("preserves budget", () => expect(result.budgetMinutes).toBe(120));
  it("does not exceed budget", () => expect(result.consumedMinutes).toBeLessThanOrEqual(120));
  it("conserves minutes", () => expect(result.remainingMinutes + result.consumedMinutes).toBe(120));
  it("records every decision", () => {
    expect(result.accepted.length + result.rejected.length).toBe(interventions.length);
  });
  it("accepts urgent cases first", () => {
    expect(result.accepted.some(item => item.caseKeys.includes(urgent.key))).toBe(true);
  });
  it("avoids overlapping case interventions", () => {
    const keys = result.accepted.flatMap(item => item.caseKeys);
    expect(new Set(keys).size).toBe(keys.length);
  });
  it("rejects unknown case", () => {
    const invalid = { ...policy, interventions: [{
      ...interventions[0]!, id: "unknown", caseKeys: ["unknown"],
    }] };
    expect(simulateInterventions(source, invalid).rejected[0]?.reason).toContain("unknown");
  });
  it("rejects overlapping cases", () => {
    const first = interventions[0]!;
    const duplicate = { ...first, id: "duplicate" };
    expect(simulateInterventions(source, {
      ...policy, interventions: [first, duplicate], budgetMinutes: 1000,
    }).rejected).toHaveLength(1);
  });
  it("rejects interventions exceeding budget", () => {
    expect(simulateInterventions(source, {
      ...policy, budgetMinutes: 0,
    }).accepted).toHaveLength(0);
  });
  it("rejects interventions exceeding maximum count", () => {
    expect(simulateInterventions(source, {
      ...policy, budgetMinutes: 1000, maximumInterventions: 1,
    }).accepted).toHaveLength(1);
  });
  it("rejects complete-coverage intervention on incomplete case", () => {
    expect(simulateInterventions(source, {
      ...policy, interventions: [{
        id: "strict", kind: "REVIEW", caseKeys: [partial.key],
        estimatedMinutes: 1, expectedBenefit: 1, requiresCompleteCoverage: true,
      }],
    }).rejected).toHaveLength(1);
  });
  it("allows recollection of incomplete case", () => {
    expect(simulateInterventions(source, {
      ...policy, interventions: [{
        id: "recollect", kind: "RECOLLECT", caseKeys: [partial.key],
        estimatedMinutes: 1, expectedBenefit: 1, requiresCompleteCoverage: false,
      }],
    }).accepted).toHaveLength(1);
  });
  it("blocks incomplete snapshot under strict policy", () => {
    expect(simulateInterventions(snapshot([urgent], false), {
      ...policy, interventions: [interventions[0]!],
    }).accepted).toHaveLength(0);
  });
  it("allows incomplete snapshot when explicit", () => {
    expect(simulateInterventions(snapshot([urgent], false), {
      ...policy, allowIncompleteCoverage: true, interventions: [interventions.find(item => item.caseKeys.includes(urgent.key))!],
    }).accepted).toHaveLength(1);
  });
  it("records warnings about simulated benefit", () => {
    expect(result.warnings.some(warning => warning.includes("planning score"))).toBe(true);
  });
});
describe("scenario portfolio", () => {
  const portfolio = compareSimulationPortfolio(source, [
    { name: "small", policy: { ...policy, budgetMinutes: 30 } },
    { name: "large", policy: { ...policy, budgetMinutes: 300 } },
  ]);
  it("evaluates both scenarios", () => expect(portfolio.scenarios).toHaveLength(2));
  it("preserves tenant", () => expect(portfolio.organizationId).toBe("org-1"));
  it("reports baseline case count", () => expect(portfolio.baselineCases).toBe(5));
  it("identifies highest benefit scenario", () => expect(portfolio.highestBenefit).toBe("large"));
  it("identifies Pareto candidates", () => expect(portfolio.paretoOptimal.length).toBeGreaterThan(0));
  it("rejects duplicate names", () => expect(() => compareSimulationPortfolio(source, [
    { name: "same", policy }, { name: "same", policy },
  ])).toThrow());
  it("handles empty portfolio", () => expect(compareSimulationPortfolio(source, []).highestBenefit).toBeNull());
});
describe("operational pulse", () => {
  const pulse = buildOperationalPulse(source, "2026-10-31T11:00:00.000Z", capacity);
  it("preserves tenant", () => expect(pulse.organizationId).toBe("org-1"));
  it("counts source cases", () => expect(pulse.cases).toBe(5));
  it("counts actionable cases", () => expect(pulse.actionable).toBe(4));
  it("includes SLA dashboard", () => expect(pulse.sla.total).toBe(4));
  it("includes capacity forecast", () => expect(pulse.capacity.demand).toHaveLength(4));
  it("flags stale review", () => expect(pulse.riskFlags).toContain("STALE_REVIEWS"));
  it("flags incomplete linked records", () => expect(pulse.riskFlags).toContain("INCOMPLETE_LINKED_RECORDS"));
  it("flags incomplete source", () => {
    expect(buildOperationalPulse(snapshot([urgent], false),
      "2026-10-31T11:00:00.000Z", capacity).riskFlags).toContain("INCOMPLETE_SOURCE");
  });
  it("exports CSV", () => expect(operationalPulseCsv(pulse)).toContain("\r\n"));
  it("exports JSON", () => expect(JSON.parse(operationalPulseJson(pulse)).organizationId).toBe("org-1"));
  it("rejects invalid assessment timestamp", () => {
    expect(() => buildOperationalPulse(source, "invalid", capacity)).toThrow();
  });
});
