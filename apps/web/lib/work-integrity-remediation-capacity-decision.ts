import { WorkInputError } from "./remediation-work-input";
import type { IntegrityCapacityPortfolioReport, IntegrityCapacityPortfolioBundle } from "./work-integrity-remediation-capacity-portfolio";
import type { IntegrityCapacityInterventionReport } from "./work-integrity-remediation-capacity-interventions";
import type { IntegrityCapacityInterventionAttributionReport } from "./work-integrity-remediation-capacity-attribution";

export type IntegrityCapacityDecisionCriterion =
  | "COMPLETED" | "ASSIGNED" | "EFFORT_COMPLETED"
  | "OUTSIDE_HORIZON" | "UNASSIGNED" | "INTERVENTION_COUNT";
export type IntegrityCapacityDecisionPolicy = {
  weights: Record<IntegrityCapacityDecisionCriterion, number>;
  requireNonDegrading: boolean;
  requireImprovement: boolean;
  minimumCompletedGain: number;
  minimumAssignedGain: number;
  maximumInterventions: number;
  includeParetoOnly: boolean;
  maximumCandidates: number;
};
export type IntegrityCapacityDecisionCandidate = {
  bundleId: string;
  interventionIds: string[];
  score: number;
  rank: number;
  eligible: boolean;
  exclusionReasons: string[];
  components: Record<IntegrityCapacityDecisionCriterion, number>;
  completedGain: number;
  assignedGain: number;
  effortGain: number;
  outsideHorizonGain: number;
  unassignedGain: number;
  interventionCount: number;
  pareto: boolean;
  degraded: boolean;
  dominatedBy: string[];
  distinctGainedCandidates: number;
  distinctLostCandidates: number;
};
export type IntegrityCapacityDecisionReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityCapacityDecisionPolicy;
  selectedBundleId: string | null;
  eligibleBundleIds: string[];
  excludedBundleIds: string[];
  candidates: IntegrityCapacityDecisionCandidate[];
  totals: {
    evaluated: number;
    eligible: number;
    excluded: number;
    selectedScore: number | null;
    maximumScore: number | null;
    minimumScore: number | null;
    tiedForFirst: number;
    byExclusionReason: Record<string, number>;
  };
  limitation: string;
};
export type IntegrityCapacityDecisionQuery = {
  bundleIds?: string[];
  onlyEligible?: boolean;
  minimumScore?: number;
  maximumScore?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityDecisionPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  candidates: IntegrityCapacityDecisionCandidate[];
};
const criteria: IntegrityCapacityDecisionCriterion[] = [
  "COMPLETED", "ASSIGNED", "EFFORT_COMPLETED",
  "OUTSIDE_HORIZON", "UNASSIGNED", "INTERVENTION_COUNT",
];
const defaultPolicy: IntegrityCapacityDecisionPolicy = {
  weights: {
    COMPLETED: 100,
    ASSIGNED: 30,
    EFFORT_COMPLETED: 5,
    OUTSIDE_HORIZON: 40,
    UNASSIGNED: 20,
    INTERVENTION_COUNT: 5,
  },
  requireNonDegrading: true,
  requireImprovement: true,
  minimumCompletedGain: 0,
  minimumAssignedGain: 0,
  maximumInterventions: 5,
  includeParetoOnly: false,
  maximumCandidates: 500,
};
function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value as Record<string, unknown>;
}
function integer(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value;
}
function decimal(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value;
}
function identifiers(value: unknown, name: string, max = 500): string[] {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + name);
  return [...new Set(value as string[])];
}
export function parseIntegrityCapacityDecisionPolicy(
  value: unknown,
): IntegrityCapacityDecisionPolicy {
  if (value === undefined) return {
    ...defaultPolicy, weights: { ...defaultPolicy.weights },
  };
  const raw = object(value, "capacity decision policy");
  if (Object.keys(raw).some(key => !Object.keys(defaultPolicy).includes(key)))
    throw new WorkInputError("INVALID", "Unknown decision policy field.");
  const weights = { ...defaultPolicy.weights };
  if (raw.weights !== undefined) {
    const requested = object(raw.weights, "decision weights");
    if (Object.keys(requested).some(key =>
      !criteria.includes(key as IntegrityCapacityDecisionCriterion)))
      throw new WorkInputError("INVALID", "Unknown decision weight.");
    for (const key of criteria)
      if (requested[key] !== undefined)
        weights[key] = decimal(requested[key], key, 0, 10000);
  }
  const flags = ["requireNonDegrading", "requireImprovement",
    "includeParetoOnly"] as const;
  const result = { ...defaultPolicy, weights };
  for (const key of flags) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid decision flag.");
      result[key] = raw[key] as boolean;
    }
  }
  for (const key of ["minimumCompletedGain", "minimumAssignedGain",
    "maximumInterventions", "maximumCandidates"] as const) {
    if (raw[key] !== undefined)
      result[key] = integer(raw[key], key,
        key.startsWith("minimum") ? 0 : 1,
        key === "maximumInterventions" ? 5 :
        key === "maximumCandidates" ? 500 : 10000);
  }
  return result;
}
function dominates(a: IntegrityCapacityPortfolioBundle,
  b: IntegrityCapacityPortfolioBundle): boolean {
  return a.completedDelta >= b.completedDelta &&
    a.assignedDelta >= b.assignedDelta &&
    a.completedEffortDelta >= b.completedEffortDelta &&
    a.outsideHorizonDelta <= b.outsideHorizonDelta &&
    a.unassignedDelta <= b.unassignedDelta &&
    (a.completedDelta > b.completedDelta ||
      a.assignedDelta > b.assignedDelta ||
      a.completedEffortDelta > b.completedEffortDelta ||
      a.outsideHorizonDelta < b.outsideHorizonDelta ||
      a.unassignedDelta < b.unassignedDelta);
}
function scoreComponents(
  bundle: IntegrityCapacityPortfolioBundle,
  policy: IntegrityCapacityDecisionPolicy,
): Record<IntegrityCapacityDecisionCriterion, number> {
  return {
    COMPLETED: bundle.completedDelta * policy.weights.COMPLETED,
    ASSIGNED: bundle.assignedDelta * policy.weights.ASSIGNED,
    EFFORT_COMPLETED: bundle.completedEffortDelta *
      policy.weights.EFFORT_COMPLETED,
    OUTSIDE_HORIZON: -bundle.outsideHorizonDelta *
      policy.weights.OUTSIDE_HORIZON,
    UNASSIGNED: -bundle.unassignedDelta * policy.weights.UNASSIGNED,
    INTERVENTION_COUNT: -bundle.interventionIds.length *
      policy.weights.INTERVENTION_COUNT,
  };
}
function exclusionReasons(
  bundle: IntegrityCapacityPortfolioBundle,
  pareto: boolean,
  policy: IntegrityCapacityDecisionPolicy,
): string[] {
  const reasons: string[] = [];
  if (policy.requireNonDegrading && bundle.degraded)
    reasons.push("DEGRADED");
  if (policy.requireImprovement && !bundle.improved)
    reasons.push("NO_IMPROVEMENT");
  if (bundle.completedDelta < policy.minimumCompletedGain)
    reasons.push("BELOW_COMPLETION_THRESHOLD");
  if (bundle.assignedDelta < policy.minimumAssignedGain)
    reasons.push("BELOW_ASSIGNMENT_THRESHOLD");
  if (bundle.interventionIds.length > policy.maximumInterventions)
    reasons.push("TOO_MANY_INTERVENTIONS");
  if (policy.includeParetoOnly && !pareto)
    reasons.push("DOMINATED");
  return reasons;
}
export function decideIntegrityCapacityPortfolio(
  portfolio: IntegrityCapacityPortfolioReport,
  policy: IntegrityCapacityDecisionPolicy = defaultPolicy,
): IntegrityCapacityDecisionReport {
  if (portfolio.bundles.length > policy.maximumCandidates)
    throw new WorkInputError("INVALID", "Portfolio exceeds decision limit.");
  const ids = new Set(portfolio.bundles.map(x => x.bundleId));
  if (ids.size !== portfolio.bundles.length)
    throw new WorkInputError("INVALID", "Duplicate decision bundle.");
  const interventionSets = new Set<string>();
  for (const bundle of portfolio.bundles) {
    if (bundle.interventionIds.length !==
        new Set(bundle.interventionIds).size ||
        !bundle.interventionIds.length)
      throw new WorkInputError("INVALID", "Invalid bundle intervention IDs.");
    const key = JSON.stringify([...bundle.interventionIds].sort());
    if (interventionSets.has(key))
      throw new WorkInputError("INVALID", "Duplicate intervention combination.");
    interventionSets.add(key);
  }
  const candidates = portfolio.bundles.map(bundle => {
    const dominatedBy = portfolio.bundles.filter(other =>
      other.bundleId !== bundle.bundleId &&
      dominates(other, bundle)).map(x => x.bundleId).sort();
    const pareto = dominatedBy.length === 0;
    const components = scoreComponents(bundle, policy);
    const score = Math.round(100 * criteria.reduce((sum, key) =>
      sum + components[key], 0)) / 100;
    if (!Number.isFinite(score))
      throw new WorkInputError("INVALID", "Decision score overflow.");
    const reasons = exclusionReasons(bundle, pareto, policy);
    return {
      bundleId: bundle.bundleId,
      interventionIds: [...bundle.interventionIds],
      score, rank: 0, eligible: reasons.length === 0,
      exclusionReasons: reasons, components,
      completedGain: bundle.completedDelta,
      assignedGain: bundle.assignedDelta,
      effortGain: bundle.completedEffortDelta,
      outsideHorizonGain: -bundle.outsideHorizonDelta,
      unassignedGain: -bundle.unassignedDelta,
      interventionCount: bundle.interventionIds.length,
      pareto, degraded: bundle.degraded, dominatedBy,
      distinctGainedCandidates: new Set(
        bundle.newlyAssignedCandidateIds).size,
      distinctLostCandidates: new Set(bundle.lostCandidateIds).size,
    };
  });
  candidates.sort((a, b) =>
    Number(b.eligible) - Number(a.eligible) ||
    b.score - a.score ||
    b.completedGain - a.completedGain ||
    b.assignedGain - a.assignedGain ||
    a.interventionCount - b.interventionCount ||
    a.bundleId.localeCompare(b.bundleId));
  candidates.forEach((candidate, index) => {
    candidate.rank = index + 1;
  });
  const eligible = candidates.filter(x => x.eligible);
  const byExclusionReason: Record<string, number> = {};
  for (const candidate of candidates)
    for (const reason of candidate.exclusionReasons)
      byExclusionReason[reason] = (byExclusionReason[reason] ?? 0) + 1;
  return {
    schemaVersion: 1,
    captureId: portfolio.captureId,
    evaluatedAt: portfolio.evaluatedAt,
    policy,
    selectedBundleId: eligible[0]?.bundleId ?? null,
    eligibleBundleIds: eligible.map(x => x.bundleId),
    excludedBundleIds: candidates.filter(x =>
      !x.eligible).map(x => x.bundleId),
    candidates,
    totals: {
      evaluated: candidates.length,
      eligible: eligible.length,
      excluded: candidates.length - eligible.length,
      selectedScore: eligible[0]?.score ?? null,
      maximumScore: candidates.length ?
        Math.max(...candidates.map(x => x.score)) : null,
      minimumScore: candidates.length ?
        Math.min(...candidates.map(x => x.score)) : null,
      tiedForFirst: eligible.filter(x =>
        x.score === eligible[0]?.score).length,
      byExclusionReason,
    },
    limitation: "Decision scores are configurable analytical preferences, not objective security risk, causal evidence, approvals, or permission to execute work. Only evaluated combinations are ranked.",
  };
}
export function parseIntegrityCapacityDecisionQuery(
  value: unknown,
): IntegrityCapacityDecisionQuery {
  const raw = object(value, "capacity decision query");
  if (Object.keys(raw).some(x => ![
    "bundleIds", "onlyEligible", "minimumScore",
    "maximumScore", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown decision query field.");
  if (raw.onlyEligible !== undefined &&
      typeof raw.onlyEligible !== "boolean")
    throw new WorkInputError("INVALID", "Invalid decision eligibility filter.");
  const minimumScore = raw.minimumScore === undefined ? undefined :
    decimal(raw.minimumScore, "minimum score", -100000000, 100000000);
  const maximumScore = raw.maximumScore === undefined ? undefined :
    decimal(raw.maximumScore, "maximum score", -100000000, 100000000);
  if (minimumScore !== undefined && maximumScore !== undefined &&
      minimumScore > maximumScore)
    throw new WorkInputError("INVALID", "Reversed decision score range.");
  return {
    ...(raw.bundleIds === undefined ? {} : {
      bundleIds: identifiers(raw.bundleIds, "bundle IDs"),
    }),
    onlyEligible: raw.onlyEligible === true,
    ...(minimumScore === undefined ? {} : { minimumScore }),
    ...(maximumScore === undefined ? {} : { maximumScore }),
    offset: integer(raw.offset ?? 0, "decision offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "decision limit", 1, 500),
  };
}
export function queryIntegrityCapacityDecision(
  report: IntegrityCapacityDecisionReport,
  query: IntegrityCapacityDecisionQuery,
): IntegrityCapacityDecisionPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const candidates = report.candidates.filter(x =>
    (!query.bundleIds || query.bundleIds.includes(x.bundleId)) &&
    (!query.onlyEligible || x.eligible) &&
    (query.minimumScore === undefined ||
      x.score >= query.minimumScore) &&
    (query.maximumScore === undefined ||
      x.score <= query.maximumScore));
  return {
    captureId: report.captureId,
    total: candidates.length,
    offset, limit,
    hasMore: offset + limit < candidates.length,
    candidates: candidates.slice(offset, offset + limit),
  };
}
export type IntegrityCapacityDecisionAudit = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  selectedBundleId: string | null;
  selectedInterventionIds: string[];
  interventionStandaloneResults: Array<{
    interventionId: string;
    assignedDelta: number | null;
    completedDelta: number | null;
    improved: boolean | null;
    degraded: boolean | null;
  }>;
  marginalAttribution: Array<{
    interventionId: string;
    marginalCompletionGain: number | null;
    marginalAssignedGain: number | null;
    pairwiseSynergies: number[];
  }>;
  candidateReasons: string[];
  completeness: {
    portfolioTruncated: boolean;
    attributionAvailable: boolean;
    standaloneResultsAvailable: boolean;
    allSelectedInterventionsRepresented: boolean;
  };
  warnings: string[];
  limitation: string;
};
export function auditIntegrityCapacityDecision(
  decision: IntegrityCapacityDecisionReport,
  portfolio: IntegrityCapacityPortfolioReport,
  interventions: IntegrityCapacityInterventionReport | null,
  attribution: IntegrityCapacityInterventionAttributionReport | null,
): IntegrityCapacityDecisionAudit {
  if (decision.captureId !== portfolio.captureId ||
      (interventions && interventions.captureId !== decision.captureId) ||
      (attribution && attribution.captureId !== decision.captureId))
    throw new WorkInputError("INVALID", "Decision audit capture mismatch.");
  const selected = portfolio.bundles.find(x =>
    x.bundleId === decision.selectedBundleId);
  if (decision.selectedBundleId !== null && !selected)
    throw new WorkInputError("INVALID", "Selected decision bundle missing.");
  const ids = selected?.interventionIds ?? [];
  const standalone = new Map(interventions?.outcomes.map(x =>
    [x.interventionId, x]) ?? []);
  const marginal = new Map(attribution?.interventions.map(x =>
    [x.interventionId, x]) ?? []);
  const allSelectedInterventionsRepresented = ids.every(id =>
    standalone.has(id));
  const warnings: string[] = [];
  if (portfolio.totals.truncated)
    warnings.push("PORTFOLIO_SEARCH_TRUNCATED");
  if (ids.length && !interventions)
    warnings.push("STANDALONE_INTERVENTIONS_UNAVAILABLE");
  if (ids.length && !attribution)
    warnings.push("MARGINAL_ATTRIBUTION_UNAVAILABLE");
  if (!allSelectedInterventionsRepresented)
    warnings.push("SELECTED_INTERVENTION_MISSING_STANDALONE");
  if (ids.some(id => !marginal.has(id)) && attribution)
    warnings.push("SELECTED_INTERVENTION_MISSING_ATTRIBUTION");
  if (!selected)
    warnings.push("NO_ELIGIBLE_BUNDLE_SELECTED");
  return {
    schemaVersion: 1, captureId: decision.captureId,
    evaluatedAt: decision.evaluatedAt,
    selectedBundleId: decision.selectedBundleId,
    selectedInterventionIds: [...ids],
    interventionStandaloneResults: ids.map(id => {
      const result = standalone.get(id);
      return {
        interventionId: id,
        assignedDelta: result?.assignedDelta ?? null,
        completedDelta: result?.completedDelta ?? null,
        improved: result?.improved ?? null,
        degraded: result?.degraded ?? null,
      };
    }),
    marginalAttribution: ids.map(id => {
      const result = marginal.get(id);
      return {
        interventionId: id,
        marginalCompletionGain: result?.marginalCompletionGain ?? null,
        marginalAssignedGain: result?.marginalAssignedGain ?? null,
        pairwiseSynergies: result?.interactions.map(x =>
          x.completionSynergy) ?? [],
      };
    }),
    candidateReasons: decision.candidates.find(x =>
      x.bundleId === decision.selectedBundleId)?.exclusionReasons ?? [],
    completeness: {
      portfolioTruncated: portfolio.totals.truncated,
      attributionAvailable: attribution !== null,
      standaloneResultsAvailable: interventions !== null,
      allSelectedInterventionsRepresented,
    },
    warnings,
    limitation: "This is a trace of the analytical selection, not an authorization or audit record of executed remediation. Inputs are scenario assumptions.",
  };
}
