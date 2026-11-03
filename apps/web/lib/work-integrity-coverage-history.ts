import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, type LinkReviewReport,
} from "./work-integrity-link-review";
import {
  evaluateIntegrityEvidenceCoverageEvents,
  type IntegrityEvidenceCoveragePolicy,
  type IntegrityEvidenceCoverageReport,
  compareIntegrityEvidenceCoverage,
} from "./work-integrity-evidence-coverage";
import {
  snapshotIntegrityReview,
} from "./work-integrity-link-timeline";

export type IntegrityCoverageCheckpoint = {
  asOf: string;
  report: IntegrityEvidenceCoverageReport;
  activeAssociations: number;
  withdrawnAssociations: number;
  auditErrors: number;
  auditWarnings: number;
};
export type IntegrityCoverageTransition = {
  from: string;
  to: string;
  beforePassed: boolean;
  afterPassed: boolean;
  improvedCases: string[];
  regressedCases: string[];
  introducedFindingCodes: string[];
  resolvedFindingCodes: string[];
  addedAssociations: number;
  withdrawnAssociations: number;
  auditErrorDelta: number;
};
export type IntegrityCoverageHistory = {
  schemaVersion: 1;
  captureId: string;
  checkpoints: IntegrityCoverageCheckpoint[];
  transitions: IntegrityCoverageTransition[];
  firstPassingAt: string | null;
  lastPassingAt: string | null;
  currentlyPassing: boolean;
  everPassing: boolean;
  continuouslyPassing: boolean;
  casesEverRegressed: string[];
  casesEverImproved: string[];
};
export type IntegrityCoverageCaseTrend = {
  caseKey: string;
  ruleId: string;
  observations: {
    at: string;
    passed: boolean;
    activeWorkItems: number;
    distinctActors: number;
    missingRequiredWorkItems: number;
  }[];
  passingCheckpoints: number;
  failingCheckpoints: number;
  longestPassingStreak: number;
  longestFailingStreak: number;
  latestPassed: boolean;
};
export type IntegrityCoverageHistoryMetrics = {
  captureId: string;
  checkpointCount: number;
  passingCheckpoints: number;
  failingCheckpoints: number;
  passingRate: number;
  regressionCount: number;
  improvementCount: number;
  auditErrorCountAtLatest: number;
  totalIntroducedFindings: number;
  totalResolvedFindings: number;
  cases: IntegrityCoverageCaseTrend[];
};
export type IntegrityCoverageHistoryInput = {
  captureId: string;
  policy: IntegrityEvidenceCoveragePolicy;
  checkpoints: string[];
};
const timestamp = (value: unknown): value is string =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
export function parseIntegrityCoverageCheckpoints(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 366 ||
      value.some(x => !timestamp(x)))
    throw new WorkInputError("INVALID", "Coverage history requires 1–366 valid timestamps.");
  const unique = new Set(value as string[]);
  if (unique.size !== value.length)
    throw new WorkInputError("INVALID", "Duplicate coverage checkpoint.");
  return [...unique].sort();
}
function checkpoint(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityEvidenceCoveragePolicy,
  asOf: string,
): IntegrityCoverageCheckpoint {
  const snapshot = snapshotIntegrityReview(captureId, events, asOf);
  const visible = events.filter(event => event.occurredAt <= asOf);
  return {
    asOf,
    report: evaluateIntegrityEvidenceCoverageEvents(captureId, visible, policy),
    activeAssociations: snapshot.active,
    withdrawnAssociations: snapshot.withdrawn,
    auditErrors: snapshot.findings.filter(x => x.severity === "ERROR").length,
    auditWarnings: snapshot.findings.filter(x => x.severity === "WARNING").length,
  };
}
export function buildIntegrityCoverageHistory(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityEvidenceCoveragePolicy,
  dates: readonly string[],
): IntegrityCoverageHistory {
  if (captureId !== policy.captureId)
    throw new WorkInputError("INVALID", "Coverage history capture mismatch.");
  const checkpoints = parseIntegrityCoverageCheckpoints(dates).map(asOf =>
    checkpoint(captureId, events, policy, asOf));
  const transitions: IntegrityCoverageTransition[] = [];
  const regressed = new Set<string>();
  const improved = new Set<string>();
  for (let i = 1; i < checkpoints.length; i++) {
    const before = checkpoints[i - 1]!;
    const after = checkpoints[i]!;
    const delta = compareIntegrityEvidenceCoverage(before.report, after.report);
    for (const key of delta.regressedCases) regressed.add(key);
    for (const key of delta.improvedCases) improved.add(key);
    transitions.push({
      from: before.asOf, to: after.asOf,
      beforePassed: before.report.passed,
      afterPassed: after.report.passed,
      improvedCases: delta.improvedCases,
      regressedCases: delta.regressedCases,
      introducedFindingCodes: delta.introducedFindings.map(x => x.code),
      resolvedFindingCodes: delta.resolvedFindings.map(x => x.code),
      addedAssociations: after.activeAssociations +
        after.withdrawnAssociations -
        before.activeAssociations - before.withdrawnAssociations,
      withdrawnAssociations: after.withdrawnAssociations - before.withdrawnAssociations,
      auditErrorDelta: after.auditErrors - before.auditErrors,
    });
  }
  const passing = checkpoints.filter(x => x.report.passed);
  return {
    schemaVersion: 1, captureId, checkpoints, transitions,
    firstPassingAt: passing[0]?.asOf ?? null,
    lastPassingAt: passing.at(-1)?.asOf ?? null,
    currentlyPassing: checkpoints.at(-1)!.report.passed,
    everPassing: passing.length > 0,
    continuouslyPassing: passing.length === checkpoints.length,
    casesEverRegressed: [...regressed].sort(),
    casesEverImproved: [...improved].sort(),
  };
}
function longestStreak(values: readonly boolean[], desired: boolean) {
  let current = 0;
  let longest = 0;
  for (const value of values) {
    current = value === desired ? current + 1 : 0;
    longest = Math.max(longest, current);
  }
  return longest;
}
export function summarizeIntegrityCoverageHistory(
  history: IntegrityCoverageHistory,
): IntegrityCoverageHistoryMetrics {
  if (!history.checkpoints.length)
    throw new WorkInputError("INVALID", "Coverage history is empty.");
  const cases = new Map<string, IntegrityCoverageCaseTrend>();
  for (const checkpoint of history.checkpoints) {
    for (const row of checkpoint.report.cases) {
      const trend = cases.get(row.caseKey) ?? {
        caseKey: row.caseKey, ruleId: row.ruleId,
        observations: [], passingCheckpoints: 0, failingCheckpoints: 0,
        longestPassingStreak: 0, longestFailingStreak: 0, latestPassed: false,
      };
      if (trend.ruleId !== row.ruleId)
        throw new WorkInputError("CONFLICT", "Coverage rule identity changed.");
      trend.observations.push({
        at: checkpoint.asOf, passed: row.passed,
        activeWorkItems: row.observed,
        distinctActors: row.distinctActors,
        missingRequiredWorkItems: row.missingWorkItemIds.length,
      });
      if (row.passed) trend.passingCheckpoints++;
      else trend.failingCheckpoints++;
      trend.latestPassed = row.passed;
      cases.set(row.caseKey, trend);
    }
  }
  for (const trend of cases.values()) {
    const values = trend.observations.map(x => x.passed);
    trend.longestPassingStreak = longestStreak(values, true);
    trend.longestFailingStreak = longestStreak(values, false);
  }
  const passingCheckpoints = history.checkpoints.filter(x => x.report.passed).length;
  return {
    captureId: history.captureId,
    checkpointCount: history.checkpoints.length,
    passingCheckpoints,
    failingCheckpoints: history.checkpoints.length - passingCheckpoints,
    passingRate: passingCheckpoints / history.checkpoints.length,
    regressionCount: history.transitions.reduce((n, x) => n + x.regressedCases.length, 0),
    improvementCount: history.transitions.reduce((n, x) => n + x.improvedCases.length, 0),
    auditErrorCountAtLatest: history.checkpoints.at(-1)!.auditErrors,
    totalIntroducedFindings: history.transitions.reduce(
      (n, x) => n + x.introducedFindingCodes.length, 0),
    totalResolvedFindings: history.transitions.reduce(
      (n, x) => n + x.resolvedFindingCodes.length, 0),
    cases: [...cases.values()].sort((a, b) => a.caseKey.localeCompare(b.caseKey)),
  };
}
export function inspectIntegrityCoverageHistory(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityEvidenceCoveragePolicy,
  dates: readonly string[],
) {
  const history = buildIntegrityCoverageHistory(captureId, events, policy, dates);
  return { history, metrics: summarizeIntegrityCoverageHistory(history) };
}
export function latestIntegrityCoverageSnapshot(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityEvidenceCoveragePolicy,
  asOf: string,
) {
  if (!timestamp(asOf))
    throw new WorkInputError("INVALID", "Invalid coverage snapshot time.");
  return checkpoint(captureId, events, policy, asOf);
}
export function coverageHistoryFromEvents(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityEvidenceCoveragePolicy,
  dates: readonly string[],
) {
  const review: LinkReviewReport = reviewIntegrityLinks(captureId, events);
  const result = inspectIntegrityCoverageHistory(captureId, events, policy, dates);
  return {
    ...result,
    auditSummary: review.counts,
    totalAuditEvents: review.totalEvents,
  };
}
