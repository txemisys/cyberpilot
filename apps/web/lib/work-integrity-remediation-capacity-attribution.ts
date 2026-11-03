import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityCapacityInterventionReport,
  IntegrityCapacityInterventionOutcome,
} from "./work-integrity-remediation-capacity-interventions";
import type {
  IntegrityCapacityPortfolioReport,
  IntegrityCapacityPortfolioBundle,
} from "./work-integrity-remediation-capacity-portfolio";

export type IntegrityCapacityInterventionAttribution = {
  interventionId: string;
  standaloneAssignedGain: number;
  standaloneCompletionGain: number;
  standaloneEffortGain: number;
  bundleAppearances: number;
  beneficialBundleAppearances: number;
  harmfulBundleAppearances: number;
  averageBundleAssignedGain: number;
  averageBundleCompletionGain: number;
  bestBundleId: string | null;
  bestBundleCompletedGain: number;
  marginalAssignedGain: number | null;
  marginalCompletionGain: number | null;
  marginalEffortGain: number | null;
  interactions: Array<{
    withInterventionId: string;
    bundleId: string;
    assignedSynergy: number;
    completionSynergy: number;
    effortSynergy: number;
  }>;
};
export type IntegrityCapacityInterventionAttributionReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  interventions: IntegrityCapacityInterventionAttribution[];
  totals: {
    interventions: number;
    representedInPortfolio: number;
    withPositiveMarginalCompletion: number;
    withPositiveMarginalAssignment: number;
    withPositiveSynergy: number;
    withNegativeSynergy: number;
    unrepresentedInterventionIds: string[];
  };
  limitation: string;
};
export type IntegrityCapacityInterventionAttributionQuery = {
  interventionIds?: string[];
  minimumBundleAppearances?: number;
  onlyPositiveSynergy?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityInterventionAttributionPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  interventions: IntegrityCapacityInterventionAttribution[];
};
function record(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid attribution query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function rank(a: IntegrityCapacityPortfolioBundle,
  b: IntegrityCapacityPortfolioBundle) {
  return b.completedDelta - a.completedDelta ||
    b.assignedDelta - a.assignedDelta ||
    b.completedEffortDelta - a.completedEffortDelta ||
    a.interventionIds.length - b.interventionIds.length ||
    a.bundleId.localeCompare(b.bundleId);
}
function bestBundle(
  bundles: IntegrityCapacityPortfolioBundle[],
): IntegrityCapacityPortfolioBundle | null {
  return [...bundles].sort(rank)[0] ?? null;
}
function positive(outcome: IntegrityCapacityInterventionOutcome) {
  return outcome.assignedDelta > 0 || outcome.completedDelta > 0 ||
    outcome.effortCompletedDelta > 0;
}
export function attributeIntegrityCapacityInterventions(
  interventions: IntegrityCapacityInterventionReport,
  portfolio: IntegrityCapacityPortfolioReport,
): IntegrityCapacityInterventionAttributionReport {
  if (interventions.captureId !== portfolio.captureId)
    throw new WorkInputError("INVALID", "Attribution capture mismatch.");
  const known = new Map(interventions.outcomes.map(x =>
    [x.interventionId, x]));
  if (known.size !== interventions.outcomes.length)
    throw new WorkInputError("INVALID", "Duplicate attribution intervention.");
  for (const bundle of portfolio.bundles) {
    if (bundle.interventionIds.some(id => !known.has(id)))
      throw new WorkInputError("INVALID", "Unknown portfolio intervention.");
  }
  const bundlesByKey = new Map(portfolio.bundles.map(x =>
    [[...x.interventionIds].sort().join("\u0000"), x]));
  const entries: IntegrityCapacityInterventionAttribution[] =
    interventions.outcomes.map(outcome => {
      const related = portfolio.bundles.filter(x =>
        x.interventionIds.includes(outcome.interventionId));
      const best = bestBundle(related);
      const marginalPairs = related.flatMap(bundle => {
        if (bundle.interventionIds.length < 2) return [];
        const remainder = bundle.interventionIds.filter(id =>
          id !== outcome.interventionId).sort();
        const without = bundlesByKey.get(remainder.join("\u0000"));
        if (!without) return [];
        return [{
          assigned: bundle.assignedDelta - without.assignedDelta,
          completed: bundle.completedDelta - without.completedDelta,
          effort: bundle.completedEffortDelta - without.completedEffortDelta,
        }];
      });
      const mean = (values: number[]) => values.length ?
        Math.round(100 * values.reduce((a, b) => a + b, 0) /
          values.length) / 100 : null;
      const interactions = related.filter(x =>
        x.interventionIds.length === 2).flatMap(bundle => {
        const otherId = bundle.interventionIds.find(id =>
          id !== outcome.interventionId);
        if (!otherId) return [];
        const other = known.get(otherId);
        if (!other) return [];
        return [{
          withInterventionId: otherId, bundleId: bundle.bundleId,
          assignedSynergy: bundle.assignedDelta -
            outcome.assignedDelta - other.assignedDelta,
          completionSynergy: bundle.completedDelta -
            outcome.completedDelta - other.completedDelta,
          effortSynergy: bundle.completedEffortDelta -
            outcome.effortCompletedDelta - other.effortCompletedDelta,
        }];
      }).sort((a, b) =>
        a.withInterventionId.localeCompare(b.withInterventionId));
      return {
        interventionId: outcome.interventionId,
        standaloneAssignedGain: outcome.assignedDelta,
        standaloneCompletionGain: outcome.completedDelta,
        standaloneEffortGain: outcome.effortCompletedDelta,
        bundleAppearances: related.length,
        beneficialBundleAppearances: related.filter(x =>
          x.improved && !x.degraded).length,
        harmfulBundleAppearances: related.filter(x => x.degraded).length,
        averageBundleAssignedGain: mean(related.map(x =>
          x.assignedDelta)) ?? 0,
        averageBundleCompletionGain: mean(related.map(x =>
          x.completedDelta)) ?? 0,
        bestBundleId: best?.bundleId ?? null,
        bestBundleCompletedGain: best?.completedDelta ?? 0,
        marginalAssignedGain: mean(marginalPairs.map(x => x.assigned)),
        marginalCompletionGain: mean(marginalPairs.map(x => x.completed)),
        marginalEffortGain: mean(marginalPairs.map(x => x.effort)),
        interactions,
      };
    });
  entries.sort((a, b) =>
    (b.marginalCompletionGain ?? b.standaloneCompletionGain) -
      (a.marginalCompletionGain ?? a.standaloneCompletionGain) ||
    (b.marginalAssignedGain ?? b.standaloneAssignedGain) -
      (a.marginalAssignedGain ?? a.standaloneAssignedGain) ||
    a.interventionId.localeCompare(b.interventionId));
  return {
    schemaVersion: 1, captureId: portfolio.captureId,
    evaluatedAt: portfolio.evaluatedAt, interventions: entries,
    totals: {
      interventions: entries.length,
      representedInPortfolio: entries.filter(x =>
        x.bundleAppearances > 0).length,
      withPositiveMarginalCompletion: entries.filter(x =>
        (x.marginalCompletionGain ?? 0) > 0).length,
      withPositiveMarginalAssignment: entries.filter(x =>
        (x.marginalAssignedGain ?? 0) > 0).length,
      withPositiveSynergy: entries.filter(x =>
        x.interactions.some(y => y.completionSynergy > 0 ||
          y.assignedSynergy > 0)).length,
      withNegativeSynergy: entries.filter(x =>
        x.interactions.some(y => y.completionSynergy < 0 ||
          y.assignedSynergy < 0)).length,
      unrepresentedInterventionIds: entries.filter(x =>
        x.bundleAppearances === 0).map(x => x.interventionId),
    },
    limitation: "Attribution is descriptive for the bounded evaluated portfolio, not causal evidence. Missing combinations, competing assignments and non-additive forecasts limit interpretation.",
  };
}
export function parseIntegrityCapacityInterventionAttributionQuery(
  value: unknown,
): IntegrityCapacityInterventionAttributionQuery {
  const raw = record(value);
  if (Object.keys(raw).some(x => ![
    "interventionIds", "minimumBundleAppearances",
    "onlyPositiveSynergy", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown attribution query field.");
  if (raw.onlyPositiveSynergy !== undefined &&
      typeof raw.onlyPositiveSynergy !== "boolean")
    throw new WorkInputError("INVALID", "Invalid attribution synergy flag.");
  let interventionIds: string[] | undefined;
  if (raw.interventionIds !== undefined) {
    if (!Array.isArray(raw.interventionIds) ||
        raw.interventionIds.length > 100 ||
        raw.interventionIds.some(x => typeof x !== "string" || !x ||
          x.length > 150 || /[\u0000-\u001f\u007f]/.test(x)))
      throw new WorkInputError("INVALID", "Invalid attribution intervention IDs.");
    interventionIds = [...new Set(raw.interventionIds as string[])];
  }
  return {
    ...(interventionIds === undefined ? {} : { interventionIds }),
    ...(raw.minimumBundleAppearances === undefined ? {} : {
      minimumBundleAppearances: integer(raw.minimumBundleAppearances,
        "minimum appearances", 0, 10000),
    }),
    onlyPositiveSynergy: raw.onlyPositiveSynergy === true,
    offset: integer(raw.offset ?? 0, "attribution offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "attribution limit", 1, 1000),
  };
}
export function queryIntegrityCapacityInterventionAttribution(
  report: IntegrityCapacityInterventionAttributionReport,
  query: IntegrityCapacityInterventionAttributionQuery,
): IntegrityCapacityInterventionAttributionPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.interventions.filter(x =>
    (!query.interventionIds ||
      query.interventionIds.includes(x.interventionId)) &&
    (query.minimumBundleAppearances === undefined ||
      x.bundleAppearances >= query.minimumBundleAppearances) &&
    (!query.onlyPositiveSynergy ||
      x.interactions.some(y => y.completionSynergy > 0 ||
        y.assignedSynergy > 0)));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    interventions: selected.slice(offset, offset + limit),
  };
}
