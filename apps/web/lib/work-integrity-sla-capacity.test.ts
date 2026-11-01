import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import {
  DEFAULT_SLA_POLICY, validateSlaPolicy, createSlaPlan, evaluateSlaCheckpoint,
  evaluateSlaPlan, compareSlaDashboards, slaDashboardCsv, slaDashboardJson,
} from "./work-integrity-sla";
import {
  DEFAULT_EFFORT_ASSUMPTIONS, validateCapacityPolicy, estimateCapacityDemand,
  analystCanReview, forecastReviewCapacity, applyCapacityScenario,
  compareCapacityScenario, capacityBottlenecks, capacityForecastCsv,
  capacityForecastJson,
} from "./work-integrity-capacity";
const makeRow = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
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
const snapshot = (rows: CaseRow[], complete = true, at = anchor) =>
  parseCaseSnapshot({ organizationId: "org-1", source: "offline", capturedAt: at,
    complete, cases: rows });
const critical = makeRow("critical", { severity: "critical" });
const attention = makeRow("attention");
const stale = makeRow("stale", { state: "STALE", reviewEventId: "event-1",
  reviewedRevision: 1 });
const reviewed = makeRow("reviewed", { state: "ACKNOWLEDGED",
  reviewEventId: "event-2", reviewedRevision: 2 });
const historical = makeRow("historical", { historicalOnly: true });
const incomplete = makeRow("incomplete", { completeCoverage: false });
const source = snapshot([critical, attention, stale, reviewed, historical, incomplete]);
const staffing = {
  profiles: [
    { analystId: "alice", availableMinutes: 180, eligibleCodes: [] as string[],
      eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">, unavailable: false },
    { analystId: "bob", availableMinutes: 180, eligibleCodes: [] as string[],
      eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">, unavailable: false },
  ],
  effort: DEFAULT_EFFORT_ASSUMPTIONS,
  excludeHistorical: true, includeReviewed: true,
  maximumCases: 100, maximumMinutes: 100000,
};
describe("SLA policy validation", () => {
  it("accepts default rules", () => {
    expect(validateSlaPolicy(DEFAULT_SLA_POLICY).rules).toHaveLength(5);
  });
  it("rejects missing priority", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      rules: DEFAULT_SLA_POLICY.rules.slice(1) })).toThrow();
  });
  it("rejects duplicate priorities", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      rules: DEFAULT_SLA_POLICY.rules.map((rule, index) =>
        index === 0 ? { ...rule, priority: "P1" as const } : rule) })).toThrow();
  });
  it("rejects zero acknowledgement deadline", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      rules: DEFAULT_SLA_POLICY.rules.map((rule, index) =>
        index === 0 ? { ...rule, acknowledgeWithinMinutes: 0 } : rule) })).toThrow();
  });
  it("rejects resolution before acknowledgement", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      rules: DEFAULT_SLA_POLICY.rules.map((rule, index) =>
        index === 0 ? { ...rule, resolveWithinMinutes: 1 } : rule) })).toThrow();
  });
  it("rejects escalation before acknowledgement", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      rules: DEFAULT_SLA_POLICY.rules.map((rule, index) =>
        index === 0 ? { ...rule, escalationAfterMinutes: 1 } : rule) })).toThrow();
  });
  it("rejects warning longer than acknowledgement", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      rules: DEFAULT_SLA_POLICY.rules.map((rule, index) =>
        index === 0 ? { ...rule, warningBeforeMinutes: 1000 } : rule) })).toThrow();
  });
  it("rejects invalid maximum cases", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      maximumCases: 0 })).toThrow();
  });
  it("rejects nonboolean flags", () => {
    expect(() => validateSlaPolicy({ ...DEFAULT_SLA_POLICY,
      pauseReviewed: 1 as never })).toThrow();
  });
});
describe("SLA planning", () => {
  const plan = createSlaPlan(source);
  it("preserves tenant", () => expect(plan.organizationId).toBe("org-1"));
  it("excludes historical by default", () => expect(plan.checkpoints).toHaveLength(5));
  it("counts excluded historical cases", () => expect(plan.excluded).toBe(1));
  it("includes historical under policy", () => expect(createSlaPlan(source, {
    ...DEFAULT_SLA_POLICY, excludeHistorical: false,
  }).checkpoints).toHaveLength(6));
  it("calculates acknowledgement deadline", () => {
    const item = plan.checkpoints.find(checkpoint => checkpoint.caseKey === critical.key)!;
    expect(item.acknowledgeBy).toBe("2026-10-31T10:30:00.000Z");
  });
  it("calculates resolution deadline", () => {
    const item = plan.checkpoints.find(checkpoint => checkpoint.caseKey === critical.key)!;
    expect(item.resolveBy).toBe("2026-10-31T14:00:00.000Z");
  });
  it("calculates escalation deadline", () => {
    const item = plan.checkpoints.find(checkpoint => checkpoint.caseKey === critical.key)!;
    expect(item.escalateAt).toBe("2026-10-31T11:00:00.000Z");
  });
  it("recognizes stale reviews", () => {
    expect(plan.checkpoints.find(item => item.caseKey === stale.key)?.staleReview).toBe(true);
  });
  it("recognizes valid reviews", () => {
    expect(plan.checkpoints.find(item => item.caseKey === reviewed.key)?.reviewed).toBe(true);
  });
  it("recognizes incomplete coverage", () => {
    expect(plan.checkpoints.find(item => item.caseKey === incomplete.key)?.completeCoverage).toBe(false);
  });
  it("rejects excessive case count", () => expect(() => createSlaPlan(source, {
    ...DEFAULT_SLA_POLICY, maximumCases: 1,
  })).toThrow());
  it("rejects noncanonical capture time", () => expect(() => createSlaPlan({
    ...source, capturedAt: "2026-10-31T10:00:00Z",
  })).toThrow());
  it("reports partial coverage", () => {
    expect(createSlaPlan(snapshot([attention], false)).complete).toBe(false);
  });
  it("does not claim actual remediation", () => {
    expect(plan.warnings.some(message => message.includes("advisory"))).toBe(true);
  });
});
describe("SLA evaluation", () => {
  const plan = createSlaPlan(snapshot([critical]));
  const checkpoint = plan.checkpoints[0]!;
  it("is on track before warning", () => {
    expect(evaluateSlaCheckpoint(checkpoint, "2026-10-31T10:00:00.000Z").phase).toBe("ON_TRACK");
  });
  it("warns before acknowledgement", () => {
    expect(evaluateSlaCheckpoint(checkpoint, "2026-10-31T10:15:00.000Z").phase).toBe("ACK_WARNING");
  });
  it("flags overdue acknowledgement", () => {
    expect(evaluateSlaCheckpoint(checkpoint, "2026-10-31T10:30:00.000Z").phase).toBe("ACK_OVERDUE");
  });
  it("flags escalation at threshold", () => {
    expect(evaluateSlaCheckpoint(checkpoint, "2026-10-31T11:00:00.000Z").phase).toBe("ESCALATED");
  });
  it("flags resolution overdue for acknowledged case", () => {
    expect(evaluateSlaCheckpoint({ ...checkpoint, reviewed: true },
      "2026-10-31T14:00:00.000Z").phase).toBe("RESOLUTION_OVERDUE");
  });
  it("does not count stale review as acknowledgement", () => {
    expect(evaluateSlaCheckpoint({ ...checkpoint, reviewed: true, staleReview: true },
      "2026-10-31T11:00:00.000Z").phase).toBe("ESCALATED");
  });
  it("supports pause after valid review", () => {
    expect(evaluateSlaCheckpoint({ ...checkpoint, reviewed: true },
      "2026-10-31T11:00:00.000Z", { pauseReviewed: true }).phase).toBe("PAUSED");
  });
  it("marks incomplete case unknown", () => {
    expect(evaluateSlaCheckpoint({ ...checkpoint, completeCoverage: false },
      "2026-10-31T11:00:00.000Z").phase).toBe("UNKNOWN");
  });
  it("marks incomplete snapshot unknown", () => {
    expect(evaluateSlaCheckpoint(checkpoint,
      "2026-10-31T11:00:00.000Z", { snapshotComplete: false }).phase).toBe("UNKNOWN");
  });
  it("rejects invalid evaluation timestamp", () => {
    expect(() => evaluateSlaCheckpoint(checkpoint, "invalid")).toThrow();
  });
  it("calculates minutes remaining", () => {
    expect(evaluateSlaCheckpoint(checkpoint,
      "2026-10-31T10:00:00.000Z").minutesUntilAcknowledgement).toBe(30);
  });
  it("evaluates all plan cases", () => {
    expect(evaluateSlaPlan(createSlaPlan(source),
      "2026-10-31T10:00:00.000Z").total).toBe(5);
  });
  it("aggregates urgent cases", () => {
    expect(evaluateSlaPlan(plan,
      "2026-10-31T11:00:00.000Z").urgent).toHaveLength(1);
  });
  it("exports JSON", () => {
    expect(JSON.parse(slaDashboardJson(evaluateSlaPlan(plan,
      "2026-10-31T11:00:00.000Z"))).total).toBe(1);
  });
  it("exports CSV", () => {
    expect(slaDashboardCsv(evaluateSlaPlan(plan,
      "2026-10-31T11:00:00.000Z"))).toContain("\r\n");
  });
  it("neutralizes spreadsheet formulas", () => {
    const injected = makeRow("=HYPERLINK");
    const output = slaDashboardCsv(evaluateSlaPlan(createSlaPlan(snapshot([injected])),
      "2026-10-31T11:00:00.000Z"));
    expect(output).toContain("'=HYPERLINK");
  });
  it("detects SLA degradation", () => {
    const before = evaluateSlaPlan(plan, "2026-10-31T10:00:00.000Z");
    const after = evaluateSlaPlan(plan, "2026-10-31T11:00:00.000Z");
    expect(compareSlaDashboards(before, after)[0]?.direction).toBe("DEGRADED");
  });
  it("rejects cross-tenant comparisons", () => {
    const before = evaluateSlaPlan(plan, "2026-10-31T10:00:00.000Z");
    expect(() => compareSlaDashboards(before, {
      ...before, organizationId: "other",
    })).toThrow();
  });
  it("marks partial comparisons uncertain", () => {
    const before = evaluateSlaPlan(plan, "2026-10-31T10:00:00.000Z");
    expect(compareSlaDashboards(before, { ...before, complete: false })[0]?.direction).toBe("UNCERTAIN");
  });
});
describe("capacity policy validation", () => {
  it("accepts staffing policy", () => expect(validateCapacityPolicy(staffing).profiles).toHaveLength(2));
  it("rejects duplicate analyst", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, profiles: [staffing.profiles[0]!, staffing.profiles[0]!],
    })).toThrow();
  });
  it("rejects negative capacity", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, profiles: [{ ...staffing.profiles[0]!, availableMinutes: -1 }],
    })).toThrow();
  });
  it("rejects invalid availability", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, profiles: [{ ...staffing.profiles[0]!, unavailable: "yes" as never }],
    })).toThrow();
  });
  it("rejects invalid eligible priority", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, profiles: [{ ...staffing.profiles[0]!,
        eligiblePriorities: ["PX"] as never }],
    })).toThrow();
  });
  it("rejects missing effort assumptions", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, effort: DEFAULT_EFFORT_ASSUMPTIONS.slice(1),
    })).toThrow();
  });
  it("rejects duplicate effort priority", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, effort: DEFAULT_EFFORT_ASSUMPTIONS.map((item, index) =>
        index === 0 ? { ...item, priority: "P1" as const } : item),
    })).toThrow();
  });
  it("rejects negative effort", () => {
    expect(() => validateCapacityPolicy({
      ...staffing, effort: DEFAULT_EFFORT_ASSUMPTIONS.map((item, index) =>
        index === 0 ? { ...item, minutesPerCase: -1 } : item),
    })).toThrow();
  });
  it("rejects zero maximum cases", () => {
    expect(() => validateCapacityPolicy({ ...staffing, maximumCases: 0 })).toThrow();
  });
  it("rejects invalid flags", () => {
    expect(() => validateCapacityPolicy({ ...staffing, includeReviewed: 1 as never })).toThrow();
  });
});
describe("capacity demand estimation", () => {
  it("excludes historical cases", () => {
    expect(estimateCapacityDemand(source, staffing)).toHaveLength(5);
  });
  it("includes historical under policy", () => {
    expect(estimateCapacityDemand(source, { ...staffing, excludeHistorical: false })).toHaveLength(6);
  });
  it("excludes reviewed when configured", () => {
    expect(estimateCapacityDemand(source, { ...staffing, includeReviewed: false })).toHaveLength(3);
  });
  it("adds effort for stale review", () => {
    const demand = estimateCapacityDemand(source, staffing);
    expect(demand.find(item => item.caseKey === stale.key)?.staleReview).toBe(true);
  });
  it("adds effort for incomplete coverage", () => {
    const demand = estimateCapacityDemand(source, staffing);
    expect(demand.find(item => item.caseKey === incomplete.key)?.incompleteCoverage).toBe(true);
  });
  it("enforces maximum case count", () => {
    expect(() => estimateCapacityDemand(source, { ...staffing, maximumCases: 1 })).toThrow();
  });
  it("enforces per-case effort limit", () => {
    expect(() => estimateCapacityDemand(source, { ...staffing, maximumMinutes: 1 })).toThrow();
  });
  it("allows unrestricted analyst", () => {
    expect(analystCanReview(staffing.profiles[0]!, estimateCapacityDemand(source, staffing)[0]!)).toBe(true);
  });
  it("rejects unavailable analyst", () => {
    expect(analystCanReview({ ...staffing.profiles[0]!, unavailable: true },
      estimateCapacityDemand(source, staffing)[0]!)).toBe(false);
  });
  it("rejects disallowed code", () => {
    expect(analystCanReview({ ...staffing.profiles[0]!, eligibleCodes: ["OTHER"] },
      estimateCapacityDemand(source, staffing)[0]!)).toBe(false);
  });
  it("rejects disallowed priority", () => {
    expect(analystCanReview({ ...staffing.profiles[0]!, eligiblePriorities: ["P4"] },
      estimateCapacityDemand(snapshot([critical]), staffing)[0]!)).toBe(false);
  });
});
describe("staffing forecasts", () => {
  const forecast = forecastReviewCapacity(source, staffing);
  it("preserves tenant", () => expect(forecast.organizationId).toBe("org-1"));
  it("counts analyst capacity", () => expect(forecast.totalAvailableMinutes).toBe(360));
  it("records all demand", () => expect(forecast.demand).toHaveLength(5));
  it("never overallocates analyst capacity", () => {
    expect(forecast.allocations.every(item =>
      item.assignedMinutes <= item.availableMinutes)).toBe(true);
  });
  it("conserves estimated minutes", () => {
    expect(forecast.totalAssignedMinutes +
      forecast.unallocated.reduce((sum, item) => sum + item.estimatedMinutes, 0))
      .toBe(forecast.totalDemandMinutes);
  });
  it("reports coverage ratio within bounds", () => {
    expect(forecast.coverageRatio).toBeGreaterThanOrEqual(0);
    expect(forecast.coverageRatio).toBeLessThanOrEqual(1);
  });
  it("reports zero staffing", () => {
    const empty = forecastReviewCapacity(source, { ...staffing, profiles: [] });
    expect(empty.unallocated).toHaveLength(5);
    expect(empty.totalAssignedMinutes).toBe(0);
  });
  it("reports unavailable staff", () => {
    const absent = forecastReviewCapacity(source, { ...staffing,
      profiles: staffing.profiles.map(profile => ({ ...profile, unavailable: true })) });
    expect(absent.totalAvailableMinutes).toBe(0);
  });
  it("rejects excessive total demand", () => {
    expect(() => forecastReviewCapacity(source, { ...staffing, maximumMinutes: 100 })).toThrow();
  });
  it("recognizes partial coverage", () => {
    expect(forecastReviewCapacity(snapshot([critical], false), staffing).complete).toBe(false);
  });
  it("identifies bottlenecks", () => {
    const empty = forecastReviewCapacity(source, { ...staffing, profiles: [] });
    expect(capacityBottlenecks(empty, []).some(item =>
      item.kind === "NO_ELIGIBLE_ANALYST")).toBe(true);
  });
  it("identifies insufficient capacity", () => {
    const small = { ...staffing, profiles: [{
      ...staffing.profiles[0]!, availableMinutes: 1,
    }] };
    expect(capacityBottlenecks(forecastReviewCapacity(source, small),
      small.profiles).some(item => item.kind === "INSUFFICIENT_MINUTES")).toBe(true);
  });
  it("identifies incomplete sources", () => {
    const partial = forecastReviewCapacity(snapshot([critical], false), staffing);
    expect(capacityBottlenecks(partial, staffing.profiles)[0]?.kind).toBe("INCOMPLETE_SOURCE");
  });
  it("exports JSON", () => expect(JSON.parse(capacityForecastJson(forecast)).version).toBe(1));
  it("exports CSV", () => expect(capacityForecastCsv(forecast)).toContain("\r\n"));
  it("neutralizes spreadsheet formula injection", () => {
    const injected = makeRow("=HYPERLINK");
    expect(capacityForecastCsv(forecastReviewCapacity(snapshot([injected]), staffing)))
      .toContain("'=HYPERLINK");
  });
});
describe("staffing what-if scenarios", () => {
  const scenario = {
    name: "additional shift",
    additionalProfiles: [{
      analystId: "carol", availableMinutes: 600,
      eligibleCodes: [] as string[],
      eligiblePriorities: [] as Array<"P0" | "P1" | "P2" | "P3" | "P4">,
      unavailable: false,
    }],
    additionalMinutesByAnalyst: { alice: 120 },
    effortMultiplier: 1,
  };
  it("adds analyst capacity", () => {
    expect(applyCapacityScenario(staffing, scenario).profiles).toHaveLength(3);
  });
  it("adds shift minutes", () => {
    expect(applyCapacityScenario(staffing, scenario).profiles.find(item =>
      item.analystId === "alice")?.availableMinutes).toBe(300);
  });
  it("increases available minutes", () => {
    expect(compareCapacityScenario(source, staffing, scenario).additionalAvailableMinutes).toBe(720);
  });
  it("does not reduce coverage with added capacity", () => {
    const result = compareCapacityScenario(source, staffing, scenario);
    expect(result.scenarioCoverage).toBeGreaterThanOrEqual(result.baselineCoverage);
  });
  it("rejects unknown analyst capacity additions", () => {
    expect(() => applyCapacityScenario(staffing, {
      ...scenario, additionalMinutesByAnalyst: { nobody: 10 },
    })).toThrow();
  });
  it("rejects duplicate new analyst", () => {
    expect(() => applyCapacityScenario(staffing, {
      ...scenario, additionalProfiles: [staffing.profiles[0]!],
    })).toThrow();
  });
  it("rejects zero effort multiplier", () => {
    expect(() => applyCapacityScenario(staffing, {
      ...scenario, effortMultiplier: 0,
    })).toThrow();
  });
  it("rejects negative additional minutes", () => {
    expect(() => applyCapacityScenario(staffing, {
      ...scenario, additionalMinutesByAnalyst: { alice: -1 },
    })).toThrow();
  });
  it("supports more conservative effort estimates", () => {
    const expanded = applyCapacityScenario(staffing, {
      ...scenario, effortMultiplier: 2,
    });
    expect(expanded.effort[0]?.minutesPerCase).toBe(DEFAULT_EFFORT_ASSUMPTIONS[0]!.minutesPerCase * 2);
  });
  it("reports remaining unallocated cases", () => {
    expect(compareCapacityScenario(source, staffing, scenario).remainingUnallocatedCases)
      .toBeGreaterThanOrEqual(0);
  });
});
