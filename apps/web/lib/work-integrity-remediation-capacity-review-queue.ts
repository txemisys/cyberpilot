import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityCapacityGovernanceReport,
  IntegrityCapacityGovernanceFinding,
} from "./work-integrity-remediation-capacity-governance";
import type {
  IntegrityCapacityDecisionReport,
} from "./work-integrity-remediation-capacity-decision";
import type {
  IntegrityCapacityPortfolioReport,
} from "./work-integrity-remediation-capacity-portfolio";

export type IntegrityCapacityReviewAction =
  | "REVIEW_ELIGIBILITY" | "EXPAND_PORTFOLIO_SEARCH"
  | "VERIFY_ASSIGNMENT_IMPACT" | "REVIEW_POLICY_STABILITY"
  | "COMPLETE_DECISION_EVIDENCE" | "REVIEW_SCENARIO_TRADEOFFS"
  | "DOCUMENT_DECISION";
export type IntegrityCapacityReviewTask = {
  taskId: string;
  action: IntegrityCapacityReviewAction;
  severity: "ERROR" | "WARNING" | "INFO";
  bundleId: string | null;
  interventionIds: string[];
  findingCodes: string[];
  reasons: string[];
  priority: number;
  position: number;
  reviewRequired: boolean;
  checklist: string[];
  affectedCandidateIds: string[];
  blockedBy: string[];
  canBeAutoResolved: false;
};
export type IntegrityCapacityReviewQueue = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  tasks: IntegrityCapacityReviewTask[];
  totals: {
    tasks: number;
    errors: number;
    warnings: number;
    info: number;
    required: number;
    affectedCandidates: number;
    byAction: Record<string, number>;
    byBundle: Record<string, number>;
  };
  limitation: string;
};
export type IntegrityCapacityReviewQuery = {
  actions?: IntegrityCapacityReviewAction[];
  severities?: IntegrityCapacityReviewTask["severity"][];
  bundleIds?: string[];
  onlyRequired?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityCapacityReviewPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  tasks: IntegrityCapacityReviewTask[];
};
const actions: IntegrityCapacityReviewAction[] = [
  "REVIEW_ELIGIBILITY", "EXPAND_PORTFOLIO_SEARCH",
  "VERIFY_ASSIGNMENT_IMPACT", "REVIEW_POLICY_STABILITY",
  "COMPLETE_DECISION_EVIDENCE", "REVIEW_SCENARIO_TRADEOFFS",
  "DOCUMENT_DECISION",
];
const severities: IntegrityCapacityReviewTask["severity"][] = [
  "ERROR", "WARNING", "INFO",
];
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid review query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function identifiers(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 300 || /[\u0000-\u001f\u007f]/.test(x)) ||
      new Set(value).size !== value.length)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as string[];
}
function actionFor(
  finding: IntegrityCapacityGovernanceFinding,
): IntegrityCapacityReviewAction {
  switch (finding.code) {
    case "NO_ELIGIBLE_SELECTION":
      return "REVIEW_ELIGIBILITY";
    case "TRUNCATED_PORTFOLIO":
      return "EXPAND_PORTFOLIO_SEARCH";
    case "SELECTION_LOSES_ASSIGNED_WORK":
    case "SELECTION_REASSIGNS_WORK":
      return "VERIFY_ASSIGNMENT_IMPACT";
    case "SELECTION_UNSTABLE":
    case "POLICY_SELECTION_CHANGED":
    case "POLICY_ELIGIBILITY_CHANGED":
    case "INCOMPLETE_SENSITIVITY":
    case "MISSING_SENSITIVITY":
      return "REVIEW_POLICY_STABILITY";
    case "MISSING_DECISION_AUDIT":
    case "INCOMPLETE_ATTRIBUTION":
    case "MISSING_STANDALONE_RESULTS":
      return "COMPLETE_DECISION_EVIDENCE";
    case "SELECTION_DEGRADES":
      return "REVIEW_SCENARIO_TRADEOFFS";
    case "SELECTION_TIED":
      return "DOCUMENT_DECISION";
  }
}
function checklistFor(
  action: IntegrityCapacityReviewAction,
): string[] {
  switch (action) {
    case "REVIEW_ELIGIBILITY":
      return [
        "Identify excluded scenarios and the exact blocking criteria.",
        "Verify whether candidate requirements and declared capacity are accurate.",
        "Recalculate rankings only after validating policy assumptions.",
      ];
    case "EXPAND_PORTFOLIO_SEARCH":
      return [
        "Review the maximum evaluations and combination-size limits.",
        "Reduce irrelevant interventions or increase the bounded search budget.",
        "Re-evaluate the candidate frontier before selecting a scenario.",
      ];
    case "VERIFY_ASSIGNMENT_IMPACT":
      return [
        "Identify affected candidate and work-item identifiers.",
        "Confirm proposed owners and prevent accidental loss of existing work.",
        "Obtain authorization before any operational reassignment.",
      ];
    case "REVIEW_POLICY_STABILITY":
      return [
        "Inspect changes in winners across tested policy variations.",
        "Review sensitive weights, thresholds, and eligibility constraints.",
        "Document why the final preference is appropriate.",
      ];
    case "COMPLETE_DECISION_EVIDENCE":
      return [
        "Generate the analytical decision trace.",
        "Include standalone intervention outcomes and attribution.",
        "Confirm all inputs reference the same capture.",
      ];
    case "REVIEW_SCENARIO_TRADEOFFS":
      return [
        "Identify each worsened indicator and affected work item.",
        "Compare against non-degrading alternatives.",
        "Record the tradeoff rationale before human approval.",
      ];
    case "DOCUMENT_DECISION":
      return [
        "Record the selected scenario and tie-break criteria.",
        "Document known modeling limitations.",
        "Keep operational authorization separate from analytical selection.",
      ];
  }
}
function priority(
  severity: IntegrityCapacityReviewTask["severity"],
  action: IntegrityCapacityReviewAction,
  affected: number,
): number {
  const base = severity === "ERROR" ? 300 :
    severity === "WARNING" ? 200 : 100;
  const actionWeight: Record<IntegrityCapacityReviewAction, number> = {
    REVIEW_ELIGIBILITY: 90,
    EXPAND_PORTFOLIO_SEARCH: 80,
    VERIFY_ASSIGNMENT_IMPACT: 100,
    REVIEW_POLICY_STABILITY: 60,
    COMPLETE_DECISION_EVIDENCE: 70,
    REVIEW_SCENARIO_TRADEOFFS: 95,
    DOCUMENT_DECISION: 10,
  };
  return base + actionWeight[action] + Math.min(50, affected);
}
export function buildIntegrityCapacityReviewQueue(
  governance: IntegrityCapacityGovernanceReport,
  decision: IntegrityCapacityDecisionReport,
  portfolio: IntegrityCapacityPortfolioReport,
): IntegrityCapacityReviewQueue {
  if (governance.captureId !== decision.captureId ||
      governance.captureId !== portfolio.captureId)
    throw new WorkInputError("INVALID", "Review queue capture mismatch.");
  const grouped = new Map<string, IntegrityCapacityReviewTask>();
  const bundles = new Map(portfolio.bundles.map(x =>
    [x.bundleId, x]));
  for (const finding of governance.findings) {
    const action = actionFor(finding);
    const bundleId = finding.relatedBundleIds.length === 1 ?
      finding.relatedBundleIds[0]! : null;
    const key = action + ":" + (bundleId ?? "GLOBAL");
    const affected = bundleId === null ? [] :
      [...new Set([
        ...(bundles.get(bundleId)?.lostCandidateIds ?? []),
        ...(bundles.get(bundleId)?.reassignedCandidateIds ?? []),
      ])].sort();
    const previous = grouped.get(key);
    if (previous) {
      previous.findingCodes.push(finding.code);
      previous.reasons.push(finding.message);
      previous.interventionIds = [...new Set([
        ...previous.interventionIds, ...finding.relatedInterventionIds,
      ])].sort();
      previous.affectedCandidateIds = [...new Set([
        ...previous.affectedCandidateIds, ...affected,
      ])].sort();
      if (severities.indexOf(finding.severity) <
          severities.indexOf(previous.severity))
        previous.severity = finding.severity;
      previous.priority = priority(previous.severity,
        action, previous.affectedCandidateIds.length);
      previous.reviewRequired = previous.severity !== "INFO";
    } else {
      grouped.set(key, {
        taskId: key, action, severity: finding.severity,
        bundleId,
        interventionIds: [...finding.relatedInterventionIds],
        findingCodes: [finding.code],
        reasons: [finding.message],
        priority: priority(finding.severity, action, affected.length),
        position: 0,
        reviewRequired: finding.severity !== "INFO",
        checklist: checklistFor(action),
        affectedCandidateIds: affected,
        blockedBy: [],
        canBeAutoResolved: false,
      });
    }
  }
  const tasks = [...grouped.values()].sort((a, b) =>
    b.priority - a.priority || a.taskId.localeCompare(b.taskId));
  const prerequisite = tasks.find(x =>
    x.action === "REVIEW_ELIGIBILITY" ||
    x.action === "EXPAND_PORTFOLIO_SEARCH");
  for (const task of tasks) {
    if (prerequisite && prerequisite.taskId !== task.taskId &&
        task.action === "DOCUMENT_DECISION")
      task.blockedBy.push(prerequisite.taskId);
  }
  tasks.forEach((task, index) => { task.position = index + 1; });
  const byAction: Record<string, number> = {};
  const byBundle: Record<string, number> = {};
  for (const task of tasks) {
    byAction[task.action] = (byAction[task.action] ?? 0) + 1;
    const key = task.bundleId ?? "GLOBAL";
    byBundle[key] = (byBundle[key] ?? 0) + 1;
  }
  return {
    schemaVersion: 1,
    captureId: governance.captureId,
    evaluatedAt: governance.evaluatedAt,
    tasks,
    totals: {
      tasks: tasks.length,
      errors: tasks.filter(x => x.severity === "ERROR").length,
      warnings: tasks.filter(x => x.severity === "WARNING").length,
      info: tasks.filter(x => x.severity === "INFO").length,
      required: tasks.filter(x => x.reviewRequired).length,
      affectedCandidates: new Set(tasks.flatMap(x =>
        x.affectedCandidateIds)).size,
      byAction, byBundle,
    },
    limitation: "Review tasks are advisory analytical checklists. They do not persist work, grant permissions, assign owners or complete remediation.",
  };
}
export function parseIntegrityCapacityReviewQuery(
  value: unknown,
): IntegrityCapacityReviewQuery {
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "actions", "severities", "bundleIds", "onlyRequired",
    "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown review query field.");
  const selectedActions = raw.actions === undefined ? undefined :
    identifiers(raw.actions, "review actions", actions.length);
  const selectedSeverities = raw.severities === undefined ? undefined :
    identifiers(raw.severities, "review severities", severities.length);
  if (selectedActions?.some(x => !actions.includes(
    x as IntegrityCapacityReviewAction)) ||
      selectedSeverities?.some(x => !severities.includes(
        x as IntegrityCapacityReviewTask["severity"])))
    throw new WorkInputError("INVALID", "Unknown review filter.");
  if (raw.onlyRequired !== undefined &&
      typeof raw.onlyRequired !== "boolean")
    throw new WorkInputError("INVALID", "Invalid review required filter.");
  return {
    ...(selectedActions === undefined ? {} : {
      actions: selectedActions as IntegrityCapacityReviewAction[],
    }),
    ...(selectedSeverities === undefined ? {} : {
      severities: selectedSeverities as IntegrityCapacityReviewTask["severity"][],
    }),
    ...(raw.bundleIds === undefined ? {} : {
      bundleIds: identifiers(raw.bundleIds, "review bundle IDs", 500),
    }),
    onlyRequired: raw.onlyRequired === true,
    offset: integer(raw.offset ?? 0, "review offset", 0, 1000000),
    limit: integer(raw.limit ?? 100, "review limit", 1, 500),
  };
}
export function queryIntegrityCapacityReviewQueue(
  queue: IntegrityCapacityReviewQueue,
  query: IntegrityCapacityReviewQuery,
): IntegrityCapacityReviewPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = queue.tasks.filter(x =>
    (!query.actions || query.actions.includes(x.action)) &&
    (!query.severities || query.severities.includes(x.severity)) &&
    (!query.bundleIds || (x.bundleId !== null &&
      query.bundleIds.includes(x.bundleId))) &&
    (!query.onlyRequired || x.reviewRequired));
  return {
    captureId: queue.captureId,
    total: selected.length,
    offset, limit,
    hasMore: offset + limit < selected.length,
    tasks: selected.slice(offset, offset + limit),
  };
}
