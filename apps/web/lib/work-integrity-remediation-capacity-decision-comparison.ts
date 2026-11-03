import { WorkInputError } from "./remediation-work-input";
import {
  decideIntegrityCapacityPortfolio,
  type IntegrityCapacityDecisionPolicy,
  type IntegrityCapacityDecisionReport,
  type IntegrityCapacityDecisionCandidate,
} from "./work-integrity-remediation-capacity-decision";
import type {
  IntegrityCapacityPortfolioReport,
} from "./work-integrity-remediation-capacity-portfolio";

export type IntegrityCapacityDecisionComparisonChange =
  | "NEWLY_ELIGIBLE" | "NEWLY_EXCLUDED" | "RANK_IMPROVED"
  | "RANK_DECLINED" | "SCORE_CHANGED" | "UNCHANGED";
export type IntegrityCapacityDecisionComparisonEntry = {
  bundleId: string;
  beforeRank: number;
  afterRank: number;
  rankDelta: number;
  beforeScore: number;
  afterScore: number;
  scoreDelta: number;
  beforeEligible: boolean;
  afterEligible: boolean;
  beforeReasons: string[];
  afterReasons: string[];
  gainedReasons: string[];
  clearedReasons: string[];
  change: IntegrityCapacityDecisionComparisonChange;
  selectedBefore: boolean;
  selectedAfter: boolean;
  completedGain: number;
  assignedGain: number;
  interventionIds: string[];
};
export type IntegrityCapacityDecisionComparisonReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  before: {
    selectedBundleId: string | null;
    selectedScore: number | null;
    eligible: number;
    excluded: number;
  };
  after: {
    selectedBundleId: string | null;
    selectedScore: number | null;
    eligible: number;
    excluded: number;
  };
  entries: IntegrityCapacityDecisionComparisonEntry[];
  totals: {
    compared: number;
    newlyEligible: number;
    newlyExcluded: number;
    rankImproved: number;
    rankDeclined: number;
    scoreChanged: number;
    unchanged: number;
    selectionChanged: boolean;
    eligibilityNetChange: number;
    maximumRankGain: number;
    maximumRankLoss: number;
    largestScoreGain: number;
    largestScoreLoss: number;
    changedBundleIds: string[];
  };
  policyChanges: Array<{
    field: string;
    before: number | boolean;
    after: number | boolean;
  }>;
  limitation: string;
};
export type IntegrityCapacityDecisionComparisonQuery = {
  changes?: IntegrityCapacityDecisionComparisonChange[];
  bundleIds?: string[];
  onlyEligibilityChanged?: boolean;
  onlySelected?: boolean;
  minimumAbsoluteRankChange?: number;
  minimumAbsoluteScoreChange?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityDecisionComparisonPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  entries: IntegrityCapacityDecisionComparisonEntry[];
};
const changes: IntegrityCapacityDecisionComparisonChange[] = [
  "NEWLY_ELIGIBLE", "NEWLY_EXCLUDED", "RANK_IMPROVED",
  "RANK_DECLINED", "SCORE_CHANGED", "UNCHANGED",
];
function record(value: unknown, name: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value as Record<string, unknown>;
}
function integer(value: unknown, name: string, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value;
}
function number(value: unknown, name: string, minimum: number, maximum: number) {
  if (typeof value !== "number" || !Number.isFinite(value) ||
      value < minimum || value > maximum)
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value;
}
function list(value: unknown, name: string, maximum: number) {
  if (!Array.isArray(value) || value.length > maximum ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value as string[];
}
function indexCandidates(report: IntegrityCapacityDecisionReport) {
  const indexed = new Map(report.candidates.map(x =>
    [x.bundleId, x]));
  if (indexed.size !== report.candidates.length)
    throw new WorkInputError("INVALID", "Duplicate comparison bundle.");
  return indexed;
}
function policyChanges(
  before: IntegrityCapacityDecisionPolicy,
  after: IntegrityCapacityDecisionPolicy,
): IntegrityCapacityDecisionComparisonReport["policyChanges"] {
  const changed: IntegrityCapacityDecisionComparisonReport["policyChanges"] = [];
  for (const key of Object.keys(before.weights) as
    Array<keyof IntegrityCapacityDecisionPolicy["weights"]>) {
    if (before.weights[key] !== after.weights[key])
      changed.push({
        field: "weights." + key,
        before: before.weights[key],
        after: after.weights[key],
      });
  }
  for (const key of [
    "requireNonDegrading", "requireImprovement",
    "minimumCompletedGain", "minimumAssignedGain",
    "maximumInterventions", "includeParetoOnly",
    "maximumCandidates",
  ] as const) {
    if (before[key] !== after[key])
      changed.push({
        field: key, before: before[key], after: after[key],
      });
  }
  return changed;
}
function classify(
  before: IntegrityCapacityDecisionCandidate,
  after: IntegrityCapacityDecisionCandidate,
): IntegrityCapacityDecisionComparisonChange {
  if (!before.eligible && after.eligible) return "NEWLY_ELIGIBLE";
  if (before.eligible && !after.eligible) return "NEWLY_EXCLUDED";
  if (after.rank < before.rank) return "RANK_IMPROVED";
  if (after.rank > before.rank) return "RANK_DECLINED";
  if (after.score !== before.score) return "SCORE_CHANGED";
  return "UNCHANGED";
}
export function compareIntegrityCapacityDecisions(
  before: IntegrityCapacityDecisionReport,
  after: IntegrityCapacityDecisionReport,
): IntegrityCapacityDecisionComparisonReport {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Decision comparison capture mismatch.");
  const previous = indexCandidates(before);
  const current = indexCandidates(after);
  if (previous.size !== current.size ||
      [...previous.keys()].some(id => !current.has(id)))
    throw new WorkInputError("INVALID", "Decision comparison bundle mismatch.");
  const entries = [...previous].map(([bundleId, earlier]) => {
    const later = current.get(bundleId)!;
    if (earlier.completedGain !== later.completedGain ||
        earlier.assignedGain !== later.assignedGain ||
        JSON.stringify(earlier.interventionIds) !==
          JSON.stringify(later.interventionIds))
      throw new WorkInputError("INVALID", "Comparison uses different scenarios.");
    const rankDelta = earlier.rank - later.rank;
    const scoreDelta = Math.round(100 *
      (later.score - earlier.score)) / 100;
    return {
      bundleId, beforeRank: earlier.rank, afterRank: later.rank,
      rankDelta, beforeScore: earlier.score,
      afterScore: later.score, scoreDelta,
      beforeEligible: earlier.eligible,
      afterEligible: later.eligible,
      beforeReasons: [...earlier.exclusionReasons],
      afterReasons: [...later.exclusionReasons],
      gainedReasons: later.exclusionReasons.filter(x =>
        !earlier.exclusionReasons.includes(x)),
      clearedReasons: earlier.exclusionReasons.filter(x =>
        !later.exclusionReasons.includes(x)),
      change: classify(earlier, later),
      selectedBefore: before.selectedBundleId === bundleId,
      selectedAfter: after.selectedBundleId === bundleId,
      completedGain: earlier.completedGain,
      assignedGain: earlier.assignedGain,
      interventionIds: [...earlier.interventionIds],
    };
  });
  entries.sort((a, b) =>
    Number(b.selectedAfter) - Number(a.selectedAfter) ||
    Number(b.selectedBefore) - Number(a.selectedBefore) ||
    Math.abs(b.rankDelta) - Math.abs(a.rankDelta) ||
    Math.abs(b.scoreDelta) - Math.abs(a.scoreDelta) ||
    a.bundleId.localeCompare(b.bundleId));
  const count = (change: IntegrityCapacityDecisionComparisonChange) =>
    entries.filter(x => x.change === change).length;
  const changed = entries.filter(x => x.change !== "UNCHANGED");
  return {
    schemaVersion: 1, captureId: before.captureId,
    evaluatedAt: after.evaluatedAt,
    before: {
      selectedBundleId: before.selectedBundleId,
      selectedScore: before.totals.selectedScore,
      eligible: before.totals.eligible,
      excluded: before.totals.excluded,
    },
    after: {
      selectedBundleId: after.selectedBundleId,
      selectedScore: after.totals.selectedScore,
      eligible: after.totals.eligible,
      excluded: after.totals.excluded,
    },
    entries,
    totals: {
      compared: entries.length,
      newlyEligible: count("NEWLY_ELIGIBLE"),
      newlyExcluded: count("NEWLY_EXCLUDED"),
      rankImproved: count("RANK_IMPROVED"),
      rankDeclined: count("RANK_DECLINED"),
      scoreChanged: count("SCORE_CHANGED"),
      unchanged: count("UNCHANGED"),
      selectionChanged: before.selectedBundleId !==
        after.selectedBundleId,
      eligibilityNetChange: after.totals.eligible -
        before.totals.eligible,
      maximumRankGain: Math.max(0, ...entries.map(x => x.rankDelta)),
      maximumRankLoss: Math.max(0, ...entries.map(x => -x.rankDelta)),
      largestScoreGain: Math.max(0, ...entries.map(x => x.scoreDelta)),
      largestScoreLoss: Math.max(0, ...entries.map(x => -x.scoreDelta)),
      changedBundleIds: changed.map(x => x.bundleId),
    },
    policyChanges: policyChanges(before.policy, after.policy),
    limitation: "This compares deterministic rankings over the same modeled scenarios; it does not establish operational improvement or causal effectiveness.",
  };
}
export function compareIntegrityCapacityDecisionPolicies(
  portfolio: IntegrityCapacityPortfolioReport,
  beforePolicy: IntegrityCapacityDecisionPolicy,
  afterPolicy: IntegrityCapacityDecisionPolicy,
): IntegrityCapacityDecisionComparisonReport {
  return compareIntegrityCapacityDecisions(
    decideIntegrityCapacityPortfolio(portfolio, beforePolicy),
    decideIntegrityCapacityPortfolio(portfolio, afterPolicy));
}
export function parseIntegrityCapacityDecisionComparisonQuery(
  value: unknown,
): IntegrityCapacityDecisionComparisonQuery {
  const raw = record(value, "decision comparison query");
  if (Object.keys(raw).some(x => ![
    "changes", "bundleIds", "onlyEligibilityChanged",
    "onlySelected", "minimumAbsoluteRankChange",
    "minimumAbsoluteScoreChange", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown comparison query field.");
  const selectedChanges = raw.changes === undefined ? undefined :
    list(raw.changes, "comparison changes", changes.length);
  if (selectedChanges?.some(x => !changes.includes(
    x as IntegrityCapacityDecisionComparisonChange)))
    throw new WorkInputError("INVALID", "Unknown comparison change.");
  for (const key of ["onlyEligibilityChanged", "onlySelected"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid comparison flag.");
  }
  return {
    ...(selectedChanges === undefined ? {} : {
      changes: selectedChanges as IntegrityCapacityDecisionComparisonChange[],
    }),
    ...(raw.bundleIds === undefined ? {} : {
      bundleIds: list(raw.bundleIds, "comparison bundle IDs", 500),
    }),
    onlyEligibilityChanged: raw.onlyEligibilityChanged === true,
    onlySelected: raw.onlySelected === true,
    ...(raw.minimumAbsoluteRankChange === undefined ? {} : {
      minimumAbsoluteRankChange: integer(raw.minimumAbsoluteRankChange,
        "minimum rank change", 0, 500),
    }),
    ...(raw.minimumAbsoluteScoreChange === undefined ? {} : {
      minimumAbsoluteScoreChange: number(raw.minimumAbsoluteScoreChange,
        "minimum score change", 0, 100000000),
    }),
    offset: integer(raw.offset ?? 0, "comparison offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "comparison limit", 1, 500),
  };
}
export function queryIntegrityCapacityDecisionComparison(
  report: IntegrityCapacityDecisionComparisonReport,
  query: IntegrityCapacityDecisionComparisonQuery,
): IntegrityCapacityDecisionComparisonPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.entries.filter(x =>
    (!query.changes || query.changes.includes(x.change)) &&
    (!query.bundleIds || query.bundleIds.includes(x.bundleId)) &&
    (!query.onlyEligibilityChanged ||
      x.beforeEligible !== x.afterEligible) &&
    (!query.onlySelected || x.selectedBefore || x.selectedAfter) &&
    (query.minimumAbsoluteRankChange === undefined ||
      Math.abs(x.rankDelta) >= query.minimumAbsoluteRankChange) &&
    (query.minimumAbsoluteScoreChange === undefined ||
      Math.abs(x.scoreDelta) >= query.minimumAbsoluteScoreChange));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    entries: selected.slice(offset, offset + limit),
  };
}
