import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityCapacityDecisionReport,
} from "./work-integrity-remediation-capacity-decision";
import type {
  IntegrityCapacitySensitivityReport,
} from "./work-integrity-remediation-capacity-sensitivity";
import type {
  IntegrityCapacityDecisionComparisonReport,
} from "./work-integrity-remediation-capacity-decision-comparison";
import type {
  IntegrityCapacityPortfolioReport,
} from "./work-integrity-remediation-capacity-portfolio";
import type {
  IntegrityCapacityDecisionAudit,
} from "./work-integrity-remediation-capacity-decision";

export type IntegrityCapacityGovernanceFindingCode =
  | "NO_ELIGIBLE_SELECTION"
  | "TRUNCATED_PORTFOLIO"
  | "SELECTION_UNSTABLE"
  | "INCOMPLETE_SENSITIVITY"
  | "MISSING_DECISION_AUDIT"
  | "INCOMPLETE_ATTRIBUTION"
  | "MISSING_STANDALONE_RESULTS"
  | "SELECTION_LOSES_ASSIGNED_WORK"
  | "SELECTION_REASSIGNS_WORK"
  | "SELECTION_DEGRADES"
  | "POLICY_SELECTION_CHANGED"
  | "POLICY_ELIGIBILITY_CHANGED"
  | "SELECTION_TIED"
  | "MISSING_SENSITIVITY";
export type IntegrityCapacityGovernanceSeverity =
  | "ERROR" | "WARNING" | "INFO";
export type IntegrityCapacityGovernanceFinding = {
  code: IntegrityCapacityGovernanceFindingCode;
  severity: IntegrityCapacityGovernanceSeverity;
  message: string;
  relatedBundleIds: string[];
  relatedInterventionIds: string[];
  metric: number | null;
  remediation: string;
};
export type IntegrityCapacityGovernancePolicy = {
  requireSensitivity: boolean;
  requireAudit: boolean;
  maximumChangedSelectionPercent: number;
  minimumSensitivityVariations: number;
  blockTruncatedPortfolio: boolean;
  blockDegradedSelection: boolean;
  blockLostAssignments: boolean;
  blockIncompleteAttribution: boolean;
  blockPolicySelectionChanges: boolean;
};
export type IntegrityCapacityGovernanceReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityCapacityGovernancePolicy;
  status: "BLOCKED" | "REVIEW_REQUIRED" | "ANALYTICALLY_ACCEPTABLE";
  selectedBundleId: string | null;
  findings: IntegrityCapacityGovernanceFinding[];
  totals: {
    errors: number;
    warnings: number;
    info: number;
    selectedInterventions: number;
    lostCandidateAssignments: number;
    reassignedCandidateAssignments: number;
    sensitivityVariations: number;
    changedSensitivitySelections: number;
    changedSelectionPercent: number | null;
    comparedPolicySelectionChanged: boolean | null;
    distinctAffectedBundles: number;
  };
  limitation: string;
};
export type IntegrityCapacityGovernanceQuery = {
  severities?: IntegrityCapacityGovernanceSeverity[];
  codes?: IntegrityCapacityGovernanceFindingCode[];
  bundleIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityGovernancePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  findings: IntegrityCapacityGovernanceFinding[];
};
const defaults: IntegrityCapacityGovernancePolicy = {
  requireSensitivity: false,
  requireAudit: true,
  maximumChangedSelectionPercent: 25,
  minimumSensitivityVariations: 3,
  blockTruncatedPortfolio: true,
  blockDegradedSelection: true,
  blockLostAssignments: true,
  blockIncompleteAttribution: false,
  blockPolicySelectionChanges: false,
};
const codes: IntegrityCapacityGovernanceFindingCode[] = [
  "NO_ELIGIBLE_SELECTION", "TRUNCATED_PORTFOLIO",
  "SELECTION_UNSTABLE", "INCOMPLETE_SENSITIVITY",
  "MISSING_DECISION_AUDIT", "INCOMPLETE_ATTRIBUTION",
  "MISSING_STANDALONE_RESULTS", "SELECTION_LOSES_ASSIGNED_WORK",
  "SELECTION_REASSIGNS_WORK", "SELECTION_DEGRADES",
  "POLICY_SELECTION_CHANGED", "POLICY_ELIGIBILITY_CHANGED",
  "SELECTION_TIED", "MISSING_SENSITIVITY",
];
const severities: IntegrityCapacityGovernanceSeverity[] = [
  "ERROR", "WARNING", "INFO",
];
function record(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function strings(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
export function parseIntegrityCapacityGovernancePolicy(
  value: unknown,
): IntegrityCapacityGovernancePolicy {
  if (value === undefined) return { ...defaults };
  const raw = record(value, "governance policy");
  if (Object.keys(raw).some(key => !Object.keys(defaults).includes(key)))
    throw new WorkInputError("INVALID", "Unknown governance policy field.");
  const result = { ...defaults };
  for (const key of [
    "requireSensitivity", "requireAudit", "blockTruncatedPortfolio",
    "blockDegradedSelection", "blockLostAssignments",
    "blockIncompleteAttribution", "blockPolicySelectionChanges",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid governance flag.");
      result[key] = raw[key] as boolean;
    }
  }
  if (raw.maximumChangedSelectionPercent !== undefined)
    result.maximumChangedSelectionPercent = integer(
      raw.maximumChangedSelectionPercent,
      "maximum changed selection percent", 0, 100);
  if (raw.minimumSensitivityVariations !== undefined)
    result.minimumSensitivityVariations = integer(
      raw.minimumSensitivityVariations,
      "minimum sensitivity variations", 1, 100);
  return result;
}
export function evaluateIntegrityCapacityGovernance(
  portfolio: IntegrityCapacityPortfolioReport,
  decision: IntegrityCapacityDecisionReport,
  sensitivity: IntegrityCapacitySensitivityReport | null,
  audit: IntegrityCapacityDecisionAudit | null,
  comparison: IntegrityCapacityDecisionComparisonReport | null,
  policy: IntegrityCapacityGovernancePolicy = defaults,
): IntegrityCapacityGovernanceReport {
  const captureId = portfolio.captureId;
  if (decision.captureId !== captureId ||
      (sensitivity && sensitivity.captureId !== captureId) ||
      (audit && audit.captureId !== captureId) ||
      (comparison && comparison.captureId !== captureId))
    throw new WorkInputError("INVALID", "Governance capture mismatch.");
  const selected = portfolio.bundles.find(x =>
    x.bundleId === decision.selectedBundleId);
  if (decision.selectedBundleId !== null && !selected)
    throw new WorkInputError("INVALID", "Governance selection not in portfolio.");
  const findings: IntegrityCapacityGovernanceFinding[] = [];
  const push = (
    code: IntegrityCapacityGovernanceFindingCode,
    severity: IntegrityCapacityGovernanceSeverity,
    message: string,
    remediation: string,
    metric: number | null = null,
    relatedBundleIds: string[] = selected ? [selected.bundleId] : [],
    relatedInterventionIds: string[] = selected ?
      [...selected.interventionIds] : [],
  ) => {
    findings.push({
      code, severity, message, remediation, metric,
      relatedBundleIds, relatedInterventionIds,
    });
  };
  if (!selected)
    push("NO_ELIGIBLE_SELECTION", "ERROR",
      "No eligible scenario was selected.",
      "Review the scenario eligibility constraints and missing capacity.");
  if (portfolio.totals.truncated)
    push("TRUNCATED_PORTFOLIO",
      policy.blockTruncatedPortfolio ? "ERROR" : "WARNING",
      "The portfolio search was truncated; the best option may be absent.",
      "Increase the bounded evaluation budget or narrow the inputs.",
      portfolio.totals.evaluated);
  if (selected?.degraded)
    push("SELECTION_DEGRADES",
      policy.blockDegradedSelection ? "ERROR" : "WARNING",
      "The selected scenario worsens at least one tracked indicator.",
      "Inspect the underlying tradeoffs and require independent review.");
  if (selected?.lostCandidateIds.length)
    push("SELECTION_LOSES_ASSIGNED_WORK",
      policy.blockLostAssignments ? "ERROR" : "WARNING",
      "The selected scenario removes existing candidate assignments.",
      "Review affected candidate ownership before any real action.",
      selected.lostCandidateIds.length);
  if (selected?.reassignedCandidateIds.length)
    push("SELECTION_REASSIGNS_WORK", "WARNING",
      "The selected scenario changes proposed candidate owners.",
      "Review reassignment impacts and validate the intended owners.",
      selected.reassignedCandidateIds.length);
  if (decision.totals.tiedForFirst > 1)
    push("SELECTION_TIED", "INFO",
      "Multiple eligible scenarios share the highest decision score.",
      "Review tie-break criteria and explain the final choice.",
      decision.totals.tiedForFirst);
  if (!audit && policy.requireAudit)
    push("MISSING_DECISION_AUDIT", "ERROR",
      "The analytical decision trace is unavailable.",
      "Generate a trace before relying on the scenario selection.");
  if (audit && !audit.completeness.attributionAvailable)
    push("INCOMPLETE_ATTRIBUTION",
      policy.blockIncompleteAttribution ? "ERROR" : "WARNING",
      "Marginal intervention attribution is unavailable.",
      "Calculate attribution using the same portfolio and intervention set.");
  if (audit && !audit.completeness.standaloneResultsAvailable)
    push("MISSING_STANDALONE_RESULTS", "WARNING",
      "Standalone intervention outcomes are unavailable.",
      "Evaluate individual interventions for comparison.");
  if (!sensitivity && policy.requireSensitivity)
    push("MISSING_SENSITIVITY", "ERROR",
      "No policy sensitivity analysis was supplied.",
      "Test bounded weight and threshold variations.");
  if (sensitivity) {
    const tested = sensitivity.stability.tested;
    if (tested < policy.minimumSensitivityVariations)
      push("INCOMPLETE_SENSITIVITY", "WARNING",
        "Too few policy variations were tested.",
        "Expand sensitivity coverage across relevant decision criteria.",
        tested);
    const changedPercent = tested ?
      Math.round(100 * sensitivity.stability.changed / tested) : 0;
    if (tested && changedPercent > policy.maximumChangedSelectionPercent)
      push("SELECTION_UNSTABLE", "WARNING",
        "The selected option changes under many tested policy variations.",
        "Review competing options and decision weight assumptions.",
        changedPercent);
  }
  if (comparison?.totals.selectionChanged)
    push("POLICY_SELECTION_CHANGED",
      policy.blockPolicySelectionChanges ? "ERROR" : "WARNING",
      "Changing the policy changes the selected scenario.",
      "Review the policy differences and changed eligibility reasons.",
      null, [
        comparison.before.selectedBundleId,
        comparison.after.selectedBundleId,
      ].filter((x): x is string => x !== null), []);
  if (comparison?.totals.eligibilityNetChange)
    push("POLICY_ELIGIBILITY_CHANGED", "INFO",
      "Policy changes alter the number of eligible scenarios.",
      "Inspect newly eligible and excluded scenario explanations.",
      comparison.totals.eligibilityNetChange, [], []);
  const order = { ERROR: 0, WARNING: 1, INFO: 2 };
  findings.sort((a, b) =>
    order[a.severity] - order[b.severity] ||
    a.code.localeCompare(b.code));
  const errors = findings.filter(x => x.severity === "ERROR").length;
  const warnings = findings.filter(x => x.severity === "WARNING").length;
  const affected = new Set(findings.flatMap(x => x.relatedBundleIds));
  return {
    schemaVersion: 1, captureId,
    evaluatedAt: decision.evaluatedAt,
    policy,
    status: errors ? "BLOCKED" : warnings ?
      "REVIEW_REQUIRED" : "ANALYTICALLY_ACCEPTABLE",
    selectedBundleId: decision.selectedBundleId,
    findings,
    totals: {
      errors, warnings,
      info: findings.filter(x => x.severity === "INFO").length,
      selectedInterventions: selected?.interventionIds.length ?? 0,
      lostCandidateAssignments: selected?.lostCandidateIds.length ?? 0,
      reassignedCandidateAssignments:
        selected?.reassignedCandidateIds.length ?? 0,
      sensitivityVariations: sensitivity?.stability.tested ?? 0,
      changedSensitivitySelections:
        sensitivity?.stability.changed ?? 0,
      changedSelectionPercent: sensitivity?.stability.tested ?
        Math.round(100 * sensitivity.stability.changed /
          sensitivity.stability.tested) : null,
      comparedPolicySelectionChanged:
        comparison?.totals.selectionChanged ?? null,
      distinctAffectedBundles: affected.size,
    },
    limitation: "Governance status applies only to hypothetical scenario analytics. ANALYTICALLY_ACCEPTABLE is not authorization, real execution readiness, or independently verified security evidence.",
  };
}
export function parseIntegrityCapacityGovernanceQuery(
  value: unknown,
): IntegrityCapacityGovernanceQuery {
  const raw = record(value, "governance query");
  if (Object.keys(raw).some(key => ![
    "severities", "codes", "bundleIds", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown governance query field.");
  const selectedSeverities = raw.severities === undefined ? undefined :
    strings(raw.severities, "governance severities", severities.length);
  const selectedCodes = raw.codes === undefined ? undefined :
    strings(raw.codes, "governance codes", codes.length);
  if (selectedSeverities?.some(x => !severities.includes(
    x as IntegrityCapacityGovernanceSeverity)) ||
      selectedCodes?.some(x => !codes.includes(
        x as IntegrityCapacityGovernanceFindingCode)))
    throw new WorkInputError("INVALID", "Unknown governance filter.");
  return {
    ...(selectedSeverities === undefined ? {} : {
      severities: selectedSeverities as IntegrityCapacityGovernanceSeverity[],
    }),
    ...(selectedCodes === undefined ? {} : {
      codes: selectedCodes as IntegrityCapacityGovernanceFindingCode[],
    }),
    ...(raw.bundleIds === undefined ? {} : {
      bundleIds: strings(raw.bundleIds, "governance bundle IDs", 500),
    }),
    offset: integer(raw.offset ?? 0, "governance offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "governance limit", 1, 500),
  };
}
export function queryIntegrityCapacityGovernance(
  report: IntegrityCapacityGovernanceReport,
  query: IntegrityCapacityGovernanceQuery,
): IntegrityCapacityGovernancePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const findings = report.findings.filter(x =>
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.codes || query.codes.includes(x.code)) &&
    (!query.bundleIds || x.relatedBundleIds.some(id =>
      query.bundleIds!.includes(id))));
  return {
    captureId: report.captureId,
    total: findings.length,
    offset, limit,
    hasMore: offset + limit < findings.length,
    findings: findings.slice(offset, offset + limit),
  };
}
