import type { CaseRow, CaseState, CaseSeverity } from "./work-integrity-cases";
import type { CaseSnapshot, SnapshotComparison } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { caseDimensions, highPriorityCases } from "./work-integrity-analytics";

/** Explicit operator-defined policies; these are triage alerts, not security verdicts. */
export type CaseAlertRule = {
  id: string;
  name: string;
  enabled: boolean;
  states: CaseState[];
  severities: (CaseSeverity | null)[];
  codes: string[];
  requireCompleteCoverage: boolean;
  onlyUnreviewed: boolean;
  minMatchingCases: number;
  maxMatchingCases: number | null;
};
export type CaseAlert = {
  ruleId: string;
  ruleName: string;
  matched: number;
  threshold: number;
  triggered: boolean;
  indeterminate: boolean;
  caseKeys: string[];
  workItemIds: string[];
  explanation: string;
};
export type CaseAlertEvaluation = {
  organizationId: string;
  capturedAt: string;
  rulesEvaluated: number;
  triggered: number;
  indeterminate: number;
  alerts: CaseAlert[];
  warnings: string[];
};
export type DeltaAlertRule = {
  id: string;
  name: string;
  enabled: boolean;
  kinds: Array<"NEW" | "CLEARED" | "CHANGED" | "INDETERMINATE">;
  minCount: number;
  requireCompleteComparison: boolean;
};
export type DeltaAlert = {
  ruleId: string;
  name: string;
  count: number;
  triggered: boolean;
  indeterminate: boolean;
  caseKeys: string[];
};
function boundedText(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
  return value.trim();
}
function boundedCount(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 10000)
    throw new Error(`Invalid ${label}.`);
  return value as number;
}
const states: CaseState[] = [
  "UNREVIEWED", "INVESTIGATING", "ACKNOWLEDGED", "DISMISSED",
  "REOPENED", "STALE", "NO_LONGER_DETECTED",
];
const severities: (CaseSeverity | null)[] = ["critical", "attention", "info", null];
export function validateCaseAlertRule(rule: CaseAlertRule): CaseAlertRule {
  const id = boundedText(rule.id, "rule ID", 100);
  const name = boundedText(rule.name, "rule name", 200);
  if (typeof rule.enabled !== "boolean" ||
      typeof rule.requireCompleteCoverage !== "boolean" ||
      typeof rule.onlyUnreviewed !== "boolean")
    throw new Error("Invalid rule flags.");
  if (!Array.isArray(rule.states) || rule.states.some(x => !states.includes(x)))
    throw new Error("Invalid states.");
  if (!Array.isArray(rule.severities) || rule.severities.some(x => !severities.includes(x)))
    throw new Error("Invalid severities.");
  if (!Array.isArray(rule.codes) || rule.codes.length > 100 ||
      rule.codes.some(x => typeof x !== "string" || !x.trim() || x.length > 100))
    throw new Error("Invalid diagnostic codes.");
  const minMatchingCases = boundedCount(rule.minMatchingCases, "minimum cases");
  if (minMatchingCases < 1) throw new Error("Minimum threshold must be positive.");
  const maxMatchingCases = rule.maxMatchingCases === null ? null :
    boundedCount(rule.maxMatchingCases, "maximum cases");
  if (maxMatchingCases !== null && maxMatchingCases < minMatchingCases)
    throw new Error("Maximum must not be below minimum.");
  return { ...rule, id, name, minMatchingCases, maxMatchingCases };
}
export function caseMatchesAlertRule(row: CaseRow, rule: CaseAlertRule): boolean {
  if (rule.states.length && !rule.states.includes(row.state)) return false;
  if (rule.severities.length && !rule.severities.includes(row.severity)) return false;
  if (rule.codes.length && !rule.codes.includes(row.code)) return false;
  if (rule.requireCompleteCoverage && !row.completeCoverage) return false;
  if (rule.onlyUnreviewed && row.reviewEventId !== null) return false;
  return true;
}
export function evaluateCaseAlerts(
  snapshot: CaseSnapshot, rules: readonly CaseAlertRule[],
): CaseAlertEvaluation {
  if (rules.length > 100) throw new Error("Too many alert rules.");
  const validated = rules.map(validateCaseAlertRule);
  const ids = validated.map(rule => rule.id);
  if (new Set(ids).size !== ids.length) throw new Error("Duplicate alert rule IDs.");
  const alerts: CaseAlert[] = [];
  for (const rule of validated) {
    if (!rule.enabled) continue;
    const matches = snapshot.cases.filter(row => caseMatchesAlertRule(row, rule));
    const indeterminate = !snapshot.complete && !rule.requireCompleteCoverage;
    const triggered = matches.length >= rule.minMatchingCases &&
      (rule.maxMatchingCases === null || matches.length <= rule.maxMatchingCases);
    alerts.push({
      ruleId: rule.id,
      ruleName: rule.name,
      matched: matches.length,
      threshold: rule.minMatchingCases,
      triggered: triggered && !indeterminate,
      indeterminate,
      caseKeys: matches.map(row => row.key).sort(),
      workItemIds: [...new Set(matches.map(row => row.workItemId))].sort(),
      explanation: indeterminate
        ? "Incomplete snapshot: alert outcome withheld."
        : triggered ? "Recorded case count meets the configured rule."
          : "Recorded case count does not meet the configured rule.",
    });
  }
  return {
    organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt,
    rulesEvaluated: alerts.length,
    triggered: alerts.filter(alert => alert.triggered).length,
    indeterminate: alerts.filter(alert => alert.indeterminate).length,
    alerts,
    warnings: [
      "Alerts describe recorded operational diagnostics and never certify a security incident.",
      "Incomplete coverage withholds conclusions unless the rule explicitly requires complete case rows.",
    ],
  };
}
export function evaluateDeltaAlerts(
  comparison: SnapshotComparison, rules: readonly DeltaAlertRule[],
): DeltaAlert[] {
  if (rules.length > 100) throw new Error("Too many delta rules.");
  const seen = new Set<string>();
  return rules.filter(rule => rule.enabled).map(rule => {
    const id = boundedText(rule.id, "delta rule ID", 100);
    const name = boundedText(rule.name, "delta rule name", 200);
    if (seen.has(id)) throw new Error("Duplicate delta rule ID.");
    seen.add(id);
    const minCount = boundedCount(rule.minCount, "delta threshold");
    if (minCount < 1 || !Array.isArray(rule.kinds) || !rule.kinds.length ||
        rule.kinds.some(kind => !["NEW", "CLEARED", "CHANGED", "INDETERMINATE"].includes(kind)))
      throw new Error("Invalid delta alert conditions.");
    const indeterminate = rule.requireCompleteComparison && !comparison.complete;
    const matches = comparison.deltas.filter(delta => rule.kinds.includes(delta.kind as typeof rule.kinds[number]));
    return {
      ruleId: id, name, count: matches.length,
      triggered: !indeterminate && matches.length >= minCount,
      indeterminate,
      caseKeys: matches.map(delta => delta.key),
    };
  });
}
export type OperationalRecommendation = {
  priority: number;
  category: string;
  caseKeys: string[];
  description: string;
  caveat: string;
};
export function operationalRecommendations(snapshot: CaseSnapshot): OperationalRecommendation[] {
  const dimensions = caseDimensions(snapshot.cases);
  const recommendations: OperationalRecommendation[] = [];
  const critical = snapshot.cases.filter(row => row.severity === "critical" && row.state === "UNREVIEWED");
  if (critical.length) recommendations.push({
    priority: 1, category: "CRITICAL_UNREVIEWED",
    caseKeys: critical.map(row => row.key),
    description: "Review untriaged critical diagnostic anomalies.",
    caveat: "Diagnostic severity is not confirmed incident severity.",
  });
  const stale = snapshot.cases.filter(row => row.state === "STALE");
  if (stale.length) recommendations.push({
    priority: 2, category: "STALE_DECISIONS",
    caseKeys: stale.map(row => row.key),
    description: "Reassess decisions tied to earlier work item revisions.",
    caveat: "A stale decision is a review consistency issue, not proof of control failure.",
  });
  const partial = snapshot.cases.filter(row => !row.completeCoverage);
  if (partial.length) recommendations.push({
    priority: 3, category: "INCOMPLETE_COVERAGE",
    caseKeys: partial.map(row => row.key),
    description: "Collect a complete bounded work-item history before inferring absence.",
    caveat: "Incomplete data cannot demonstrate remediation or closure.",
  });
  if (dimensions.unreviewed) recommendations.push({
    priority: 4, category: "UNREVIEWED",
    caseKeys: snapshot.cases.filter(row => row.state === "UNREVIEWED").map(row => row.key),
    description: "Assign a human review to remaining unreviewed diagnostics.",
    caveat: "A human review is not an independent technical verification.",
  });
  if (!snapshot.complete) recommendations.push({
    priority: 5, category: "SNAPSHOT_COMPLETENESS",
    caseKeys: [],
    description: "Repeat collection with complete page and linked-record coverage.",
    caveat: "No case clearance can be established from a partial capture.",
  });
  return recommendations.sort((a, b) => a.priority - b.priority);
}
export function caseAlertDigest(snapshot: CaseSnapshot, rules: readonly CaseAlertRule[]) {
  const evaluated = evaluateCaseAlerts(snapshot, rules);
  return {
    ...evaluated,
    dimensions: caseDimensions(snapshot.cases),
    priorityQueue: highPriorityCases(snapshot.cases, 25),
    recommendations: operationalRecommendations(snapshot),
  };
}
export function compareAndAlert(
  before: CaseSnapshot, after: CaseSnapshot,
  caseRules: readonly CaseAlertRule[], deltaRules: readonly DeltaAlertRule[],
) {
  const comparison = compareCaseSnapshots(before, after);
  return {
    comparison,
    caseAlerts: evaluateCaseAlerts(after, caseRules),
    deltaAlerts: evaluateDeltaAlerts(comparison, deltaRules),
    recommendations: operationalRecommendations(after),
  };
}
