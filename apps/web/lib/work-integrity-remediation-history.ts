import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  buildIntegrityEvidencePortfolio,
  type IntegrityEvidencePortfolioInput,
} from "./work-integrity-evidence-portfolio";
import {
  analyzeIntegrityPortfolioRisk,
  type IntegrityPortfolioRiskWeights,
} from "./work-integrity-portfolio-risk";
import {
  buildIntegrityRemediationPlan,
  compareIntegrityRemediationPlans,
  type IntegrityRemediationPlan,
  type IntegrityRemediationPlanDelta,
  type IntegrityRemediationCandidate,
} from "./work-integrity-remediation-plan";

export type IntegrityRemediationCheckpoint = {
  at: string;
  plan: IntegrityRemediationPlan;
  riskMeanCases: number;
  riskMeanWorkItems: number;
  policyFailures: number;
  activeAssociations: number;
  withdrawnAssociations: number;
};
export type IntegrityRemediationTransition = {
  from: string;
  to: string;
  delta: IntegrityRemediationPlanDelta;
  riskCaseDelta: number;
  riskWorkDelta: number;
  policyFailureDelta: number;
  activeAssociationDelta: number;
  withdrawnAssociationDelta: number;
  candidateDelta: number;
  newUrgentCandidates: string[];
  resolvedUrgentCandidates: string[];
};
export type IntegrityRemediationTrend = {
  id: string;
  action: IntegrityRemediationCandidate["action"];
  caseKey: string | null;
  workItemId: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  observedCheckpoints: number;
  missingCheckpoints: number;
  current: boolean;
  everUrgent: boolean;
  currentPriority: IntegrityRemediationCandidate["priority"] | null;
  priorityHistory: {
    at: string;
    priority: IntegrityRemediationCandidate["priority"];
    estimatedRiskReduction: number;
    blocked: boolean;
  }[];
  longestOpenStreak: number;
  longestResolvedStreak: number;
};
export type IntegrityRemediationHistory = {
  schemaVersion: 1;
  captureId: string;
  checkpoints: IntegrityRemediationCheckpoint[];
  transitions: IntegrityRemediationTransition[];
  trends: IntegrityRemediationTrend[];
  totals: {
    checkpointCount: number;
    candidateIntroductions: number;
    candidateResolutions: number;
    priorityEscalations: number;
    priorityDeescalations: number;
    newlyBlocked: number;
    newlyExecutable: number;
    currentlyOpen: number;
    currentlyUrgent: number;
    everUrgent: number;
    continuouslyOpen: number;
    totalCaseRiskChange: number;
    totalWorkRiskChange: number;
    policyFailureChange: number;
  };
};
export type IntegrityRemediationHistoryQuery = {
  actions?: IntegrityRemediationCandidate["action"][];
  caseKeys?: string[];
  workItemIds?: string[];
  currentOnly?: boolean;
  urgentOnly?: boolean;
  minimumObservations?: number;
  offset?: number;
  limit?: number;
};
export type IntegrityRemediationHistoryPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  trends: IntegrityRemediationTrend[];
};
const compare = (a: string, b: string) => a.localeCompare(b);
const validDate = (value: unknown): value is string =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const priorities = ["P0", "P1", "P2", "P3"] as const;
function validCheckpoints(values: readonly string[]) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 100 ||
      values.some(x => !validDate(x)))
    throw new WorkInputError("INVALID", "Invalid remediation checkpoints.");
  const sorted = [...new Set(values)].sort(compare);
  if (sorted.length !== values.length)
    throw new WorkInputError("INVALID", "Duplicate remediation checkpoint.");
  return sorted;
}
function streak(values: readonly boolean[], desired: boolean) {
  let longest = 0;
  let current = 0;
  for (const value of values) {
    current = value === desired ? current + 1 : 0;
    if (current > longest) longest = current;
  }
  return longest;
}
function urgent(candidate: IntegrityRemediationCandidate) {
  return candidate.priority === "P0" || candidate.priority === "P1";
}
function snapshot(
  input: IntegrityEvidencePortfolioInput,
  events: readonly IntegrityLinkHistoryEvent[],
  at: string,
  weights?: IntegrityPortfolioRiskWeights,
): IntegrityRemediationCheckpoint {
  const portfolio = buildIntegrityEvidencePortfolio({ ...input, asOf: at }, events);
  const risk = analyzeIntegrityPortfolioRisk(portfolio, weights);
  const plan = buildIntegrityRemediationPlan(portfolio, risk);
  return {
    at, plan, riskMeanCases: risk.meanCaseRisk,
    riskMeanWorkItems: risk.meanWorkRisk,
    policyFailures: portfolio.totals.policyFailures,
    activeAssociations: portfolio.totals.activeAssociations,
    withdrawnAssociations: portfolio.totals.withdrawnAssociations,
  };
}
function transition(
  before: IntegrityRemediationCheckpoint,
  after: IntegrityRemediationCheckpoint,
): IntegrityRemediationTransition {
  const delta = compareIntegrityRemediationPlans(before.plan, after.plan);
  const previous = new Map(before.plan.candidates.map(x => [x.id, x]));
  const current = new Map(after.plan.candidates.map(x => [x.id, x]));
  const newUrgentCandidates: string[] = [];
  const resolvedUrgentCandidates: string[] = [];
  for (const [id, row] of current) {
    if (urgent(row) && !urgent(previous.get(id) ?? {
      ...row, priority: "P3",
    })) newUrgentCandidates.push(id);
  }
  for (const [id, row] of previous) {
    if (urgent(row) && !urgent(current.get(id) ?? {
      ...row, priority: "P3",
    })) resolvedUrgentCandidates.push(id);
  }
  return {
    from: before.at, to: after.at, delta,
    riskCaseDelta: after.riskMeanCases - before.riskMeanCases,
    riskWorkDelta: after.riskMeanWorkItems - before.riskMeanWorkItems,
    policyFailureDelta: after.policyFailures - before.policyFailures,
    activeAssociationDelta: after.activeAssociations - before.activeAssociations,
    withdrawnAssociationDelta: after.withdrawnAssociations -
      before.withdrawnAssociations,
    candidateDelta: after.plan.totals.candidates - before.plan.totals.candidates,
    newUrgentCandidates: newUrgentCandidates.sort(compare),
    resolvedUrgentCandidates: resolvedUrgentCandidates.sort(compare),
  };
}
function buildTrends(
  checkpoints: readonly IntegrityRemediationCheckpoint[],
): IntegrityRemediationTrend[] {
  const all = new Map<string, IntegrityRemediationCandidate>();
  for (const checkpoint of checkpoints) {
    for (const item of checkpoint.plan.candidates) all.set(item.id, item);
  }
  const result: IntegrityRemediationTrend[] = [];
  for (const [id, item] of all) {
    const observations = checkpoints.map(checkpoint => ({
      at: checkpoint.at,
      candidate: checkpoint.plan.candidates.find(x => x.id === id),
    }));
    const present = observations.filter(x => x.candidate !== undefined);
    const last = observations.at(-1)!.candidate;
    const priorityHistory = present.map(x => ({
      at: x.at, priority: x.candidate!.priority,
      estimatedRiskReduction: x.candidate!.estimatedRiskReduction,
      blocked: x.candidate!.blockedBy.length > 0,
    }));
    result.push({
      id, action: item.action, caseKey: item.caseKey,
      workItemId: item.workItemId,
      firstSeenAt: present[0]!.at,
      lastSeenAt: present.at(-1)!.at,
      observedCheckpoints: present.length,
      missingCheckpoints: checkpoints.length - present.length,
      current: last !== undefined,
      everUrgent: present.some(x => urgent(x.candidate!)),
      currentPriority: last?.priority ?? null,
      priorityHistory,
      longestOpenStreak: streak(observations.map(x =>
        x.candidate !== undefined), true),
      longestResolvedStreak: streak(observations.map(x =>
        x.candidate !== undefined), false),
    });
  }
  return result.sort((a, b) =>
    Number(b.current) - Number(a.current) ||
    Number(b.everUrgent) - Number(a.everUrgent) ||
    compare(a.id, b.id));
}
function totals(
  checkpoints: readonly IntegrityRemediationCheckpoint[],
  transitions: readonly IntegrityRemediationTransition[],
  trends: readonly IntegrityRemediationTrend[],
): IntegrityRemediationHistory["totals"] {
  const first = checkpoints[0]!;
  const last = checkpoints.at(-1)!;
  let priorityEscalations = 0;
  let priorityDeescalations = 0;
  for (const change of transitions) {
    for (const row of change.delta.reprioritized) {
      if (priorities.indexOf(row.to) < priorities.indexOf(row.from))
        priorityEscalations++;
      else priorityDeescalations++;
    }
  }
  return {
    checkpointCount: checkpoints.length,
    candidateIntroductions: transitions.reduce((sum, x) =>
      sum + x.delta.added.length, 0),
    candidateResolutions: transitions.reduce((sum, x) =>
      sum + x.delta.removed.length, 0),
    priorityEscalations, priorityDeescalations,
    newlyBlocked: transitions.reduce((sum, x) =>
      sum + x.delta.newlyBlocked.length, 0),
    newlyExecutable: transitions.reduce((sum, x) =>
      sum + x.delta.newlyExecutable.length, 0),
    currentlyOpen: trends.filter(x => x.current).length,
    currentlyUrgent: last.plan.candidates.filter(urgent).length,
    everUrgent: trends.filter(x => x.everUrgent).length,
    continuouslyOpen: trends.filter(x =>
      x.observedCheckpoints === checkpoints.length).length,
    totalCaseRiskChange: last.riskMeanCases - first.riskMeanCases,
    totalWorkRiskChange: last.riskMeanWorkItems - first.riskMeanWorkItems,
    policyFailureChange: last.policyFailures - first.policyFailures,
  };
}
export function buildIntegrityRemediationHistory(
  input: IntegrityEvidencePortfolioInput,
  events: readonly IntegrityLinkHistoryEvent[],
  dates: readonly string[],
  weights?: IntegrityPortfolioRiskWeights,
): IntegrityRemediationHistory {
  const checkpoints = validCheckpoints(dates).map(at =>
    snapshot(input, events, at, weights));
  const transitions = checkpoints.slice(1).map((after, index) =>
    transition(checkpoints[index]!, after));
  const trends = buildTrends(checkpoints);
  return {
    schemaVersion: 1, captureId: input.captureId,
    checkpoints, transitions, trends,
    totals: totals(checkpoints, transitions, trends),
  };
}
function optionalIds(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function optionalInt(value: unknown, label: string, fallback: number, max: number) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
export function parseIntegrityRemediationHistoryQuery(
  value: unknown,
): IntegrityRemediationHistoryQuery {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid history query.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(x => ![
    "actions", "caseKeys", "workItemIds", "currentOnly",
    "urgentOnly", "minimumObservations", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown history query field.");
  if (raw.currentOnly !== undefined && typeof raw.currentOnly !== "boolean")
    throw new WorkInputError("INVALID", "Invalid current flag.");
  if (raw.urgentOnly !== undefined && typeof raw.urgentOnly !== "boolean")
    throw new WorkInputError("INVALID", "Invalid urgent flag.");
  return {
    ...(raw.actions !== undefined ? { actions: optionalIds(raw.actions, "actions") as IntegrityRemediationCandidate["action"][] } : {}),
    ...(raw.caseKeys !== undefined ? { caseKeys: optionalIds(raw.caseKeys, "case keys")! } : {}),
    ...(raw.workItemIds !== undefined ? { workItemIds: optionalIds(raw.workItemIds, "work IDs")! } : {}),
    currentOnly: raw.currentOnly === true,
    urgentOnly: raw.urgentOnly === true,
    minimumObservations: optionalInt(
      raw.minimumObservations, "minimum observations", 0, 100),
    offset: optionalInt(raw.offset, "offset", 0, 1000000),
    limit: optionalInt(raw.limit, "limit", 100, 1000),
  };
}
export function queryIntegrityRemediationHistory(
  history: IntegrityRemediationHistory,
  query: IntegrityRemediationHistoryQuery,
): IntegrityRemediationHistoryPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid history pagination.");
  const selected = history.trends.filter(x =>
    (!query.actions || query.actions.includes(x.action)) &&
    (!query.caseKeys || (x.caseKey !== null &&
      query.caseKeys.includes(x.caseKey))) &&
    (!query.workItemIds || (x.workItemId !== null &&
      query.workItemIds.includes(x.workItemId))) &&
    (!query.currentOnly || x.current) &&
    (!query.urgentOnly || x.everUrgent) &&
    x.observedCheckpoints >= (query.minimumObservations ?? 0));
  return {
    captureId: history.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    trends: selected.slice(offset, offset + limit),
  };
}
export function summarizeIntegrityRemediationHistory(
  history: IntegrityRemediationHistory,
) {
  const byAction = new Map<string, {
    action: string;
    everObserved: number;
    currentlyOpen: number;
    everUrgent: number;
    meanObservedCheckpoints: number;
  }>();
  for (const trend of history.trends) {
    const row = byAction.get(trend.action) ?? {
      action: trend.action, everObserved: 0,
      currentlyOpen: 0, everUrgent: 0, meanObservedCheckpoints: 0,
    };
    row.everObserved++;
    if (trend.current) row.currentlyOpen++;
    if (trend.everUrgent) row.everUrgent++;
    row.meanObservedCheckpoints += trend.observedCheckpoints;
    byAction.set(trend.action, row);
  }
  const actions = [...byAction.values()].map(x => ({
    ...x, meanObservedCheckpoints: x.meanObservedCheckpoints / x.everObserved,
  })).sort((a, b) => b.currentlyOpen - a.currentlyOpen ||
    compare(a.action, b.action));
  return {
    captureId: history.captureId,
    totals: history.totals,
    actions,
    highestPersistence: [...history.trends].sort((a, b) =>
      b.observedCheckpoints - a.observedCheckpoints ||
      compare(a.id, b.id)).slice(0, 20),
    recentIntroductions: history.transitions.at(-1)?.delta.added ?? [],
    recentResolutions: history.transitions.at(-1)?.delta.removed ?? [],
    latestRegressions: history.transitions.at(-1)?.newUrgentCandidates ?? [],
  };
}
