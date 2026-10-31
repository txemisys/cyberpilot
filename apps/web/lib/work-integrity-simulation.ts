import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";
import { createSlaPlan, evaluateSlaPlan, type SlaPolicy, DEFAULT_SLA_POLICY } from "./work-integrity-sla";
import { forecastReviewCapacity, type CapacityPolicy } from "./work-integrity-capacity";

/**
 * Offline operational simulation. All inputs are immutable snapshots and
 * explicit assumptions; no production data or external resources are mutated.
 */
export type SimulationIntervention = {
  id: string;
  kind: "REVIEW" | "REASSESS" | "RECOLLECT" | "DEFER";
  caseKeys: string[];
  estimatedMinutes: number;
  expectedBenefit: number;
  requiresCompleteCoverage: boolean;
};
export type SimulationPolicy = {
  interventions: SimulationIntervention[];
  budgetMinutes: number;
  maximumInterventions: number;
  allowIncompleteCoverage: boolean;
  prioritiseUrgent: boolean;
};
export type SimulationDecision = {
  interventionId: string;
  kind: SimulationIntervention["kind"];
  caseKeys: string[];
  accepted: boolean;
  estimatedMinutes: number;
  expectedBenefit: number;
  reason: string;
};
export type SimulationResult = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  budgetMinutes: number;
  consumedMinutes: number;
  remainingMinutes: number;
  totalExpectedBenefit: number;
  accepted: SimulationDecision[];
  rejected: SimulationDecision[];
  affectedCaseKeys: string[];
  warnings: string[];
};
export type SimulationPortfolio = {
  organizationId: string;
  baselineCases: number;
  scenarios: SimulationResult[];
  highestBenefit: string | null;
  highestEfficiency: string | null;
  paretoOptimal: string[];
};
function checkId(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > 200 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${name}.`);
}
function integer(value: number, name: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error(`Invalid ${name}.`);
}
export function validateSimulationPolicy(input: SimulationPolicy): SimulationPolicy {
  if (!input || !Array.isArray(input.interventions) || input.interventions.length > 10000)
    throw new Error("Invalid simulation interventions.");
  integer(input.budgetMinutes, "budget", 0, 10_000_000);
  integer(input.maximumInterventions, "intervention limit", 1, 10000);
  if (typeof input.allowIncompleteCoverage !== "boolean" ||
      typeof input.prioritiseUrgent !== "boolean")
    throw new Error("Invalid simulation policy flags.");
  const ids = new Set<string>();
  const interventions = input.interventions.map(item => {
    checkId(item.id, "intervention ID");
    if (ids.has(item.id)) throw new Error("Duplicate intervention ID.");
    ids.add(item.id);
    if (!["REVIEW", "REASSESS", "RECOLLECT", "DEFER"].includes(item.kind))
      throw new Error("Unknown intervention type.");
    if (!Array.isArray(item.caseKeys) || !item.caseKeys.length ||
        item.caseKeys.length > 10000)
      throw new Error("Invalid intervention case keys.");
    for (const key of item.caseKeys) checkId(key, "case key");
    if (new Set(item.caseKeys).size !== item.caseKeys.length)
      throw new Error("Duplicate case key in intervention.");
    integer(item.estimatedMinutes, "intervention effort", 1, 1_000_000);
    if (!Number.isFinite(item.expectedBenefit) ||
        item.expectedBenefit < 0 || item.expectedBenefit > 1_000_000)
      throw new Error("Invalid expected benefit.");
    if (typeof item.requiresCompleteCoverage !== "boolean")
      throw new Error("Invalid intervention coverage flag.");
    return { ...item, caseKeys: [...item.caseKeys].sort() };
  });
  return { ...input, interventions };
}
export function proposeInterventions(
  snapshot: CaseSnapshot,
  effortByPriority: Record<"P0" | "P1" | "P2" | "P3" | "P4", number>,
): SimulationIntervention[] {
  const priorities = ["P0", "P1", "P2", "P3", "P4"] as const;
  for (const priority of priorities)
    integer(effortByPriority[priority], `effort for ${priority}`, 1, 100000);
  return buildReviewWorklist(snapshot).entries.filter(entry => !entry.historicalOnly)
    .map(entry => {
      const kind: SimulationIntervention["kind"] =
        !entry.completeCoverage ? "RECOLLECT" :
        entry.state === "STALE" ? "REASSESS" : "REVIEW";
      const weight = 5 - priorities.indexOf(entry.priority);
      return {
        id: `${kind}:${entry.caseKey}`, kind,
        caseKeys: [entry.caseKey], estimatedMinutes: effortByPriority[entry.priority],
        expectedBenefit: weight,
        requiresCompleteCoverage: kind !== "RECOLLECT",
      };
    });
}
export function simulateInterventions(
  snapshot: CaseSnapshot, input: SimulationPolicy,
): SimulationResult {
  const policy = validateSimulationPolicy(input);
  const cases = new Map(snapshot.cases.map(row => [row.key, row]));
  const queue = buildReviewWorklist(snapshot).entries;
  const rank = new Map(queue.map((item, index) => [item.caseKey, index]));
  const sorted = [...policy.interventions].sort((a, b) => {
    if (policy.prioritiseUrgent) {
      const aRank = Math.min(...a.caseKeys.map(key => rank.get(key) ?? Number.MAX_SAFE_INTEGER));
      const bRank = Math.min(...b.caseKeys.map(key => rank.get(key) ?? Number.MAX_SAFE_INTEGER));
      if (aRank !== bRank) return aRank - bRank;
    }
    const aRatio = a.expectedBenefit / a.estimatedMinutes;
    const bRatio = b.expectedBenefit / b.estimatedMinutes;
    return bRatio - aRatio || a.id.localeCompare(b.id);
  });
  const occupied = new Set<string>();
  const accepted: SimulationDecision[] = [];
  const rejected: SimulationDecision[] = [];
  let consumedMinutes = 0;
  let totalExpectedBenefit = 0;
  for (const item of sorted) {
    const missing = item.caseKeys.some(key => !cases.has(key));
    const incomplete = item.caseKeys.some(key => !cases.get(key)?.completeCoverage);
    const overlapping = item.caseKeys.some(key => occupied.has(key));
    const reason = missing ? "Intervention references an unknown case." :
      !snapshot.complete && !policy.allowIncompleteCoverage
        ? "Source snapshot is incomplete." :
      incomplete && item.requiresCompleteCoverage
        ? "Intervention requires complete linked coverage." :
      overlapping ? "One or more cases are already assigned to another intervention." :
      accepted.length >= policy.maximumInterventions
        ? "Maximum accepted interventions reached." :
      consumedMinutes + item.estimatedMinutes > policy.budgetMinutes
        ? "Insufficient remaining time budget." : "Accepted within configured constraints.";
    const decision: SimulationDecision = {
      interventionId: item.id, kind: item.kind,
      caseKeys: item.caseKeys, accepted: reason.startsWith("Accepted"),
      estimatedMinutes: item.estimatedMinutes,
      expectedBenefit: item.expectedBenefit, reason,
    };
    if (!decision.accepted) {
      rejected.push(decision);
      continue;
    }
    accepted.push(decision);
    consumedMinutes += item.estimatedMinutes;
    totalExpectedBenefit += item.expectedBenefit;
    for (const key of item.caseKeys) occupied.add(key);
  }
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, complete: snapshot.complete,
    budgetMinutes: policy.budgetMinutes, consumedMinutes,
    remainingMinutes: policy.budgetMinutes - consumedMinutes,
    totalExpectedBenefit, accepted, rejected,
    affectedCaseKeys: [...occupied].sort(),
    warnings: [
      "Expected benefit is an explicit planning score, not observed remediation.",
      "Simulation does not perform reviews, recollection, or any production changes.",
      ...(!snapshot.complete ? ["Incomplete collection may omit other cases."] : []),
    ],
  };
}
export function compareSimulationPortfolio(
  snapshot: CaseSnapshot, policies: Array<{ name: string; policy: SimulationPolicy }>,
): SimulationPortfolio {
  if (!Array.isArray(policies) || policies.length > 100)
    throw new Error("Too many simulation scenarios.");
  const names = new Set<string>();
  const scenarios = policies.map(item => {
    checkId(item.name, "scenario name");
    if (names.has(item.name)) throw new Error("Duplicate scenario name.");
    names.add(item.name);
    return { ...simulateInterventions(snapshot, item.policy), scenarioName: item.name };
  });
  const benefit = [...scenarios].sort((a, b) =>
    b.totalExpectedBenefit - a.totalExpectedBenefit ||
    a.scenarioName.localeCompare(b.scenarioName))[0];
  const efficiency = [...scenarios].sort((a, b) =>
    (b.consumedMinutes ? b.totalExpectedBenefit / b.consumedMinutes : 0) -
    (a.consumedMinutes ? a.totalExpectedBenefit / a.consumedMinutes : 0) ||
    a.scenarioName.localeCompare(b.scenarioName))[0];
  const paretoOptimal = scenarios.filter(candidate => !scenarios.some(other =>
    other !== candidate &&
    other.totalExpectedBenefit >= candidate.totalExpectedBenefit &&
    other.consumedMinutes <= candidate.consumedMinutes &&
    (other.totalExpectedBenefit > candidate.totalExpectedBenefit ||
      other.consumedMinutes < candidate.consumedMinutes)))
    .map(item => item.scenarioName).sort();
  return {
    organizationId: snapshot.organizationId, baselineCases: snapshot.cases.length,
    scenarios, highestBenefit: benefit?.scenarioName ?? null,
    highestEfficiency: efficiency?.scenarioName ?? null, paretoOptimal,
  };
}
export type OperationalPulse = {
  organizationId: string;
  capturedAt: string;
  evaluatedAt: string;
  complete: boolean;
  cases: number;
  priorityCounts: Record<string, number>;
  sla: ReturnType<typeof evaluateSlaPlan>;
  capacity: ReturnType<typeof forecastReviewCapacity>;
  actionable: number;
  riskFlags: string[];
};
export function buildOperationalPulse(
  snapshot: CaseSnapshot, evaluatedAt: string,
  capacityPolicy: CapacityPolicy,
  slaPolicy: SlaPolicy = DEFAULT_SLA_POLICY,
): OperationalPulse {
  const queue = buildReviewWorklist(snapshot);
  const priorityCounts: Record<string, number> = {};
  for (const item of queue.entries)
    priorityCounts[item.priority] = (priorityCounts[item.priority] ?? 0) + 1;
  const sla = evaluateSlaPlan(createSlaPlan(snapshot, slaPolicy), evaluatedAt, slaPolicy);
  const capacity = forecastReviewCapacity(snapshot, capacityPolicy);
  const riskFlags = [
    ...(!snapshot.complete ? ["INCOMPLETE_SOURCE"] : []),
    ...(sla.urgent.length ? ["SLA_THRESHOLD"] : []),
    ...(capacity.unallocated.length ? ["CAPACITY_SHORTFALL"] : []),
    ...(queue.entries.some(item => !item.completeCoverage) ? ["INCOMPLETE_LINKED_RECORDS"] : []),
    ...(queue.entries.some(item => item.state === "STALE") ? ["STALE_REVIEWS"] : []),
  ];
  return {
    organizationId: snapshot.organizationId, capturedAt: snapshot.capturedAt,
    evaluatedAt, complete: snapshot.complete, cases: snapshot.cases.length,
    priorityCounts, sla, capacity,
    actionable: queue.entries.filter(item => !item.historicalOnly).length,
    riskFlags,
  };
}
export function operationalPulseCsv(pulse: OperationalPulse): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const escaped = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + escaped.replace(/"/g, '""') + '"';
  };
  const rows = [["metric", "value"].map(safe).join(",")];
  for (const [metric, value] of [
    ["organizationId", pulse.organizationId], ["capturedAt", pulse.capturedAt],
    ["evaluatedAt", pulse.evaluatedAt], ["complete", pulse.complete],
    ["cases", pulse.cases], ["actionable", pulse.actionable],
    ["capacityCoverageRatio", pulse.capacity.coverageRatio],
    ["unallocatedCases", pulse.capacity.unallocated.length],
    ["urgentSlaCases", pulse.sla.urgent.length],
    ["riskFlags", pulse.riskFlags.join(";")],
  ] as Array<[string, unknown]>) rows.push([metric, value].map(safe).join(","));
  return rows.join("\r\n") + "\r\n";
}
export function operationalPulseJson(pulse: OperationalPulse): string {
  return JSON.stringify(pulse, null, 2) + "\n";
}
