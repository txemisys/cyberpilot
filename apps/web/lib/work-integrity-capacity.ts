import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";

/**
 * Deterministic offline workload forecasting and staffing recommendations.
 * Uses observed case queues only; never claims measured arrival rates or
 * predicts actual completion without an explicit assumption.
 */
export type CapacityTier = "P0" | "P1" | "P2" | "P3" | "P4";
export type CapacityProfile = {
  analystId: string;
  availableMinutes: number;
  eligibleCodes: string[];
  eligiblePriorities: CapacityTier[];
  unavailable: boolean;
};
export type EffortAssumption = {
  priority: CapacityTier;
  minutesPerCase: number;
  additionalMinutesForStaleReview: number;
  additionalMinutesForIncompleteCoverage: number;
};
export type CapacityPolicy = {
  profiles: CapacityProfile[];
  effort: EffortAssumption[];
  excludeHistorical: boolean;
  includeReviewed: boolean;
  maximumCases: number;
  maximumMinutes: number;
};
export type CapacityDemand = {
  caseKey: string;
  workItemId: string;
  code: string;
  priority: CapacityTier;
  estimatedMinutes: number;
  staleReview: boolean;
  incompleteCoverage: boolean;
};
export type CapacityAllocation = {
  analystId: string;
  availableMinutes: number;
  assignedMinutes: number;
  remainingMinutes: number;
  caseKeys: string[];
  utilization: number;
};
export type CapacityForecast = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  demand: CapacityDemand[];
  allocations: CapacityAllocation[];
  unallocated: CapacityDemand[];
  totalDemandMinutes: number;
  totalAvailableMinutes: number;
  totalAssignedMinutes: number;
  coverageRatio: number;
  warnings: string[];
};
export const DEFAULT_EFFORT_ASSUMPTIONS: EffortAssumption[] = [
  { priority: "P0", minutesPerCase: 90, additionalMinutesForStaleReview: 45, additionalMinutesForIncompleteCoverage: 60 },
  { priority: "P1", minutesPerCase: 60, additionalMinutesForStaleReview: 30, additionalMinutesForIncompleteCoverage: 45 },
  { priority: "P2", minutesPerCase: 45, additionalMinutesForStaleReview: 25, additionalMinutesForIncompleteCoverage: 30 },
  { priority: "P3", minutesPerCase: 30, additionalMinutesForStaleReview: 15, additionalMinutesForIncompleteCoverage: 20 },
  { priority: "P4", minutesPerCase: 20, additionalMinutesForStaleReview: 10, additionalMinutesForIncompleteCoverage: 15 },
];
const tiers: CapacityTier[] = ["P0", "P1", "P2", "P3", "P4"];
function checkIdentifier(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > 200 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
}
function positiveBound(value: number, label: string, maximum: number, allowZero = false): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum)
    throw new Error(`Invalid ${label}.`);
}
export function validateCapacityPolicy(input: CapacityPolicy): CapacityPolicy {
  if (!input || !Array.isArray(input.profiles) ||
      input.profiles.length > 1000 ||
      !Array.isArray(input.effort) || input.effort.length !== 5)
    throw new Error("Invalid staffing profile or effort assumptions.");
  positiveBound(input.maximumCases, "case limit", 100000);
  positiveBound(input.maximumMinutes, "minutes limit", 10_000_000);
  if (typeof input.excludeHistorical !== "boolean" ||
      typeof input.includeReviewed !== "boolean")
    throw new Error("Invalid capacity flags.");
  const seen = new Set<string>();
  const profiles = input.profiles.map(profile => {
    checkIdentifier(profile.analystId, "analyst ID");
    if (seen.has(profile.analystId)) throw new Error("Duplicate analyst profile.");
    seen.add(profile.analystId);
    positiveBound(profile.availableMinutes, "available minutes", 100000, true);
    if (typeof profile.unavailable !== "boolean")
      throw new Error("Invalid analyst availability flag.");
    if (!Array.isArray(profile.eligibleCodes) || profile.eligibleCodes.length > 1000 ||
        profile.eligibleCodes.some(code => typeof code !== "string" || !code.trim() || code.length > 200))
      throw new Error("Invalid eligible diagnostic codes.");
    if (!Array.isArray(profile.eligiblePriorities) ||
        profile.eligiblePriorities.some(priority => !tiers.includes(priority)))
      throw new Error("Invalid eligible priorities.");
    return {
      ...profile,
      eligibleCodes: [...new Set(profile.eligibleCodes)].sort(),
      eligiblePriorities: [...new Set(profile.eligiblePriorities)].sort(),
    };
  }).sort((a, b) => a.analystId.localeCompare(b.analystId));
  const seenTiers = new Set<string>();
  const effort = input.effort.map(assumption => {
    if (!tiers.includes(assumption.priority) || seenTiers.has(assumption.priority))
      throw new Error("Invalid or duplicate effort priority.");
    seenTiers.add(assumption.priority);
    positiveBound(assumption.minutesPerCase, "effort minutes", 100000);
    positiveBound(assumption.additionalMinutesForStaleReview, "stale review effort", 100000, true);
    positiveBound(assumption.additionalMinutesForIncompleteCoverage, "coverage effort", 100000, true);
    return { ...assumption };
  }).sort((a, b) => a.priority.localeCompare(b.priority));
  return { ...input, profiles, effort };
}
export function estimateCapacityDemand(
  snapshot: CaseSnapshot, input: CapacityPolicy,
): CapacityDemand[] {
  const policy = validateCapacityPolicy(input);
  const effort = new Map(policy.effort.map(item => [item.priority, item]));
  const queue = buildReviewWorklist(snapshot).entries.filter(item =>
    (!policy.excludeHistorical || !item.historicalOnly) &&
    (policy.includeReviewed || !item.reviewEventId));
  if (queue.length > policy.maximumCases)
    throw new Error("Workload exceeds configured maximum case count.");
  return queue.map(item => {
    const assumption = effort.get(item.priority)!;
    const staleReview = item.state === "STALE";
    const incompleteCoverage = !item.completeCoverage;
    const estimatedMinutes = assumption.minutesPerCase +
      (staleReview ? assumption.additionalMinutesForStaleReview : 0) +
      (incompleteCoverage ? assumption.additionalMinutesForIncompleteCoverage : 0);
    if (estimatedMinutes > policy.maximumMinutes)
      throw new Error("Estimated case effort exceeds configured maximum minutes.");
    return {
      caseKey: item.caseKey, workItemId: item.workItemId, code: item.code,
      priority: item.priority, estimatedMinutes, staleReview, incompleteCoverage,
    };
  });
}
export function analystCanReview(
  analyst: CapacityProfile, demand: CapacityDemand,
): boolean {
  return !analyst.unavailable &&
    (analyst.eligibleCodes.length === 0 || analyst.eligibleCodes.includes(demand.code)) &&
    (analyst.eligiblePriorities.length === 0 ||
      analyst.eligiblePriorities.includes(demand.priority));
}
export function forecastReviewCapacity(
  snapshot: CaseSnapshot, input: CapacityPolicy,
): CapacityForecast {
  const policy = validateCapacityPolicy(input);
  const demand = estimateCapacityDemand(snapshot, policy);
  const totalDemandMinutes = demand.reduce((sum, item) => sum + item.estimatedMinutes, 0);
  if (totalDemandMinutes > policy.maximumMinutes)
    throw new Error("Total estimated effort exceeds configured maximum minutes.");
  const allocations = policy.profiles.map(profile => ({
    analystId: profile.analystId,
    availableMinutes: profile.unavailable ? 0 : profile.availableMinutes,
    assignedMinutes: 0, remainingMinutes: profile.unavailable ? 0 : profile.availableMinutes,
    caseKeys: [] as string[], utilization: 0,
  }));
  const byId = new Map(policy.profiles.map(profile => [profile.analystId, profile]));
  const unallocated: CapacityDemand[] = [];
  for (const item of demand) {
    const eligible = allocations.filter(allocation =>
      allocation.remainingMinutes >= item.estimatedMinutes &&
      analystCanReview(byId.get(allocation.analystId)!, item))
      .sort((a, b) => {
        const left = a.availableMinutes ? a.assignedMinutes / a.availableMinutes : 1;
        const right = b.availableMinutes ? b.assignedMinutes / b.availableMinutes : 1;
        return left - right || a.analystId.localeCompare(b.analystId);
      });
    const target = eligible[0];
    if (!target) {
      unallocated.push(item);
      continue;
    }
    target.assignedMinutes += item.estimatedMinutes;
    target.remainingMinutes -= item.estimatedMinutes;
    target.caseKeys.push(item.caseKey);
    target.utilization = target.assignedMinutes / target.availableMinutes;
  }
  const totalAvailableMinutes = allocations.reduce((sum, item) => sum + item.availableMinutes, 0);
  const totalAssignedMinutes = allocations.reduce((sum, item) => sum + item.assignedMinutes, 0);
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, complete: snapshot.complete,
    demand, allocations, unallocated, totalDemandMinutes,
    totalAvailableMinutes, totalAssignedMinutes,
    coverageRatio: totalDemandMinutes === 0 ? 1 : totalAssignedMinutes / totalDemandMinutes,
    warnings: [
      "Effort is a configurable assumption, not measured analyst productivity.",
      "The forecast is an offline plan and does not assign real ownership or change permissions.",
      ...(!snapshot.complete ? ["Partial source coverage may understate workload."] : []),
      ...(unallocated.length ? ["Some cases exceed eligible analyst capacity."] : []),
    ],
  };
}
export type CapacityScenario = {
  name: string;
  additionalProfiles: CapacityProfile[];
  additionalMinutesByAnalyst: Record<string, number>;
  effortMultiplier: number;
};
export type CapacityScenarioResult = {
  name: string;
  baselineCoverage: number;
  scenarioCoverage: number;
  additionalAssignedMinutes: number;
  additionalAvailableMinutes: number;
  remainingUnallocatedCases: number;
  warnings: string[];
};
export function applyCapacityScenario(
  policy: CapacityPolicy, scenario: CapacityScenario,
): CapacityPolicy {
  checkIdentifier(scenario.name, "scenario name");
  if (!Number.isFinite(scenario.effortMultiplier) ||
      scenario.effortMultiplier <= 0 || scenario.effortMultiplier > 10)
    throw new Error("Invalid effort multiplier.");
  if (!Array.isArray(scenario.additionalProfiles))
    throw new Error("Invalid additional analyst profiles.");
  if (!scenario.additionalMinutesByAnalyst ||
      typeof scenario.additionalMinutesByAnalyst !== "object" ||
      Array.isArray(scenario.additionalMinutesByAnalyst))
    throw new Error("Invalid additional capacity map.");
  const additions = scenario.additionalMinutesByAnalyst;
  for (const [id, minutes] of Object.entries(additions)) {
    checkIdentifier(id, "capacity analyst ID");
    positiveBound(minutes, "additional capacity", 100000, true);
    if (!policy.profiles.some(profile => profile.analystId === id))
      throw new Error("Additional capacity references an unknown analyst.");
  }
  const profiles = [
    ...policy.profiles.map(profile => ({
      ...profile, availableMinutes: profile.availableMinutes +
        (additions[profile.analystId] ?? 0),
    })),
    ...scenario.additionalProfiles,
  ];
  const effort = policy.effort.map(item => ({
    ...item,
    minutesPerCase: Math.max(1, Math.ceil(item.minutesPerCase * scenario.effortMultiplier)),
    additionalMinutesForStaleReview: Math.ceil(item.additionalMinutesForStaleReview * scenario.effortMultiplier),
    additionalMinutesForIncompleteCoverage: Math.ceil(item.additionalMinutesForIncompleteCoverage * scenario.effortMultiplier),
  }));
  return validateCapacityPolicy({ ...policy, profiles, effort });
}
export function compareCapacityScenario(
  snapshot: CaseSnapshot, policy: CapacityPolicy, scenario: CapacityScenario,
): CapacityScenarioResult {
  const baseline = forecastReviewCapacity(snapshot, policy);
  const projected = forecastReviewCapacity(snapshot, applyCapacityScenario(policy, scenario));
  return {
    name: scenario.name, baselineCoverage: baseline.coverageRatio,
    scenarioCoverage: projected.coverageRatio,
    additionalAssignedMinutes: projected.totalAssignedMinutes - baseline.totalAssignedMinutes,
    additionalAvailableMinutes: projected.totalAvailableMinutes - baseline.totalAvailableMinutes,
    remainingUnallocatedCases: projected.unallocated.length,
    warnings: [
      "Scenario results depend on the explicit effort assumptions and greedy allocation order.",
      ...projected.warnings,
    ],
  };
}
export type CapacityBottleneck = {
  kind: "NO_ELIGIBLE_ANALYST" | "INSUFFICIENT_MINUTES" | "INCOMPLETE_SOURCE";
  caseKey: string | null;
  code: string | null;
  priority: CapacityTier | null;
  missingMinutes: number;
  explanation: string;
};
export function capacityBottlenecks(
  forecast: CapacityForecast, profiles: readonly CapacityProfile[],
): CapacityBottleneck[] {
  const bottlenecks: CapacityBottleneck[] = [];
  if (!forecast.complete) bottlenecks.push({
    kind: "INCOMPLETE_SOURCE", caseKey: null, code: null, priority: null,
    missingMinutes: 0, explanation: "Source collection is incomplete.",
  });
  for (const demand of forecast.unallocated) {
    const eligible = profiles.filter(profile => analystCanReview(profile, demand));
    const maximumRemaining = Math.max(0, ...forecast.allocations
      .filter(allocation => eligible.some(profile => profile.analystId === allocation.analystId))
      .map(allocation => allocation.remainingMinutes));
    bottlenecks.push({
      kind: eligible.length ? "INSUFFICIENT_MINUTES" : "NO_ELIGIBLE_ANALYST",
      caseKey: demand.caseKey, code: demand.code, priority: demand.priority,
      missingMinutes: eligible.length ? Math.max(0, demand.estimatedMinutes - maximumRemaining) : demand.estimatedMinutes,
      explanation: eligible.length
        ? "Eligible analysts have insufficient remaining uninterrupted capacity."
        : "No available analyst is eligible for this diagnostic and priority.",
    });
  }
  return bottlenecks;
}
export function capacityForecastCsv(forecast: CapacityForecast): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const escaped = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + escaped.replace(/"/g, '""') + '"';
  };
  const owner = new Map(forecast.allocations.flatMap(allocation =>
    allocation.caseKeys.map(key => [key, allocation.analystId] as const)));
  const lines = [["caseKey", "workItemId", "code", "priority", "estimatedMinutes",
    "analystId", "staleReview", "incompleteCoverage"].map(safe).join(",")];
  for (const item of forecast.demand)
    lines.push([item.caseKey, item.workItemId, item.code, item.priority,
      item.estimatedMinutes, owner.get(item.caseKey) ?? "",
      item.staleReview, item.incompleteCoverage].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function capacityForecastJson(forecast: CapacityForecast): string {
  return JSON.stringify(forecast, null, 2) + "\n";
}
