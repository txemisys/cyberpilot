import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  buildIntegrityEvidencePortfolio,
  type IntegrityEvidencePortfolioInput,
  type IntegrityEvidencePortfolio,
} from "./work-integrity-evidence-portfolio";
import {
  analyzeIntegrityPortfolioRisk,
  type IntegrityPortfolioRiskReport,
  type IntegrityPortfolioRiskWeights,
} from "./work-integrity-portfolio-risk";

export type IntegrityRemediationAction =
  | "LINK_REQUIRED_WORK"
  | "RELINK_WITHDRAWN_WORK"
  | "CREATE_WORK_ASSIGNMENT"
  | "REVIEW_AUDIT_ERROR"
  | "REVIEW_AUDIT_WARNING"
  | "REVIEW_UNCOVERED_CASE"
  | "REVIEW_UNREFERENCED_WORK"
  | "REVIEW_SHARED_DEPENDENCY"
  | "REVIEW_WITHDRAWN_ONLY_CASE"
  | "REVIEW_POLICY_CONFLICT";
export type IntegrityRemediationPriority = "P0" | "P1" | "P2" | "P3";
export type IntegrityRemediationCandidate = {
  id: string;
  action: IntegrityRemediationAction;
  priority: IntegrityRemediationPriority;
  caseKey: string | null;
  workItemId: string | null;
  auditId: string | null;
  policyIndex: number | null;
  reasonCodes: string[];
  explanation: string;
  estimatedRiskReduction: number;
  dependencies: string[];
  blockedBy: string[];
  executable: boolean;
};
export type IntegrityRemediationPlan = {
  schemaVersion: 1;
  captureId: string;
  generatedAt: string | null;
  candidates: IntegrityRemediationCandidate[];
  totals: {
    candidates: number;
    executable: number;
    advisory: number;
    blocked: number;
    p0: number;
    p1: number;
    p2: number;
    p3: number;
    affectedCases: number;
    affectedWorkItems: number;
    estimatedRiskReduction: number;
  };
};
export type IntegrityRemediationPlanQuery = {
  priorities?: IntegrityRemediationPriority[];
  actions?: IntegrityRemediationAction[];
  caseKeys?: string[];
  workItemIds?: string[];
  executableOnly?: boolean;
  includeBlocked?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityRemediationPlanPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  candidates: IntegrityRemediationCandidate[];
};
export type IntegrityRemediationPlanDelta = {
  captureId: string;
  added: IntegrityRemediationCandidate[];
  removed: IntegrityRemediationCandidate[];
  reprioritized: {
    id: string;
    from: IntegrityRemediationPriority;
    to: IntegrityRemediationPriority;
  }[];
  newlyExecutable: string[];
  newlyBlocked: string[];
  unchanged: number;
};
const compare = (a: string, b: string) => a.localeCompare(b);
const unique = (values: readonly string[]) => [...new Set(values)].sort(compare);
const actions: IntegrityRemediationAction[] = [
  "LINK_REQUIRED_WORK", "RELINK_WITHDRAWN_WORK",
  "CREATE_WORK_ASSIGNMENT", "REVIEW_AUDIT_ERROR",
  "REVIEW_AUDIT_WARNING", "REVIEW_UNCOVERED_CASE",
  "REVIEW_UNREFERENCED_WORK", "REVIEW_SHARED_DEPENDENCY",
  "REVIEW_WITHDRAWN_ONLY_CASE", "REVIEW_POLICY_CONFLICT",
];
const priorities: IntegrityRemediationPriority[] = ["P0", "P1", "P2", "P3"];
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected remediation query object.");
  return value as Record<string, unknown>;
}
function array<T extends string>(
  value: unknown, label: string, options?: readonly T[],
): T[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x) ||
        (options !== undefined && !options.includes(x))))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as T[])];
}
function integer(value: unknown, label: string, fallback: number, max: number) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
export function parseIntegrityRemediationPlanQuery(
  value: unknown,
): IntegrityRemediationPlanQuery {
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "priorities", "actions", "caseKeys", "workItemIds",
    "executableOnly", "includeBlocked", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown remediation query field.");
  for (const field of ["executableOnly", "includeBlocked"]) {
    if (raw[field] !== undefined && typeof raw[field] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid " + field);
  }
  return {
    priorities: array(raw.priorities, "priorities", priorities),
    actions: array(raw.actions, "actions", actions),
    caseKeys: array(raw.caseKeys, "case keys"),
    workItemIds: array(raw.workItemIds, "work IDs"),
    executableOnly: raw.executableOnly === true,
    includeBlocked: raw.includeBlocked !== false,
    offset: integer(raw.offset, "offset", 0, 1000000),
    limit: integer(raw.limit, "limit", 100, 1000),
  };
}
function priority(score: number, severe = false): IntegrityRemediationPriority {
  if (severe || score >= 75) return "P0";
  if (score >= 50) return "P1";
  if (score >= 25) return "P2";
  return "P3";
}
function id(
  action: IntegrityRemediationAction,
  caseKey: string | null,
  workItemId: string | null,
  auditId: string | null,
  policyIndex: number | null,
) {
  return JSON.stringify([action, caseKey, workItemId, auditId, policyIndex]);
}
function candidate(
  action: IntegrityRemediationAction,
  reasonCodes: string[],
  explanation: string,
  score: number,
  options: {
    caseKey?: string | null;
    workItemId?: string | null;
    auditId?: string | null;
    policyIndex?: number | null;
    executable?: boolean;
    blockedBy?: string[];
    dependencies?: string[];
    severe?: boolean;
  } = {},
): IntegrityRemediationCandidate {
  const caseKey = options.caseKey ?? null;
  const workItemId = options.workItemId ?? null;
  const auditId = options.auditId ?? null;
  const policyIndex = options.policyIndex ?? null;
  return {
    id: id(action, caseKey, workItemId, auditId, policyIndex),
    action, priority: priority(score, options.severe),
    caseKey, workItemId, auditId, policyIndex,
    reasonCodes: unique(reasonCodes), explanation,
    estimatedRiskReduction: Math.max(0, Math.min(100, score)),
    dependencies: unique(options.dependencies ?? []),
    blockedBy: unique(options.blockedBy ?? []),
    executable: options.executable === true &&
      (options.blockedBy?.length ?? 0) === 0,
  };
}
function caseRisk(report: IntegrityPortfolioRiskReport, key: string) {
  return report.cases.find(x => x.caseKey === key)?.score ?? 0;
}
function workRisk(report: IntegrityPortfolioRiskReport, key: string) {
  return report.workItems.find(x => x.workItemId === key)?.score ?? 0;
}
function fromMissingWork(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationCandidate[] {
  const result: IntegrityRemediationCandidate[] = [];
  for (const row of portfolio.cases) {
    const score = caseRisk(risk, row.caseKey);
    for (const workItemId of row.missingWorkItemIds) {
      const previouslyLinked = row.withdrawnWorkItemIds.includes(workItemId);
      result.push(candidate(
        previouslyLinked ? "RELINK_WITHDRAWN_WORK" : "LINK_REQUIRED_WORK",
        ["MISSING_REQUIRED_WORK", ...(previouslyLinked ? ["PREVIOUSLY_WITHDRAWN"] : [])],
        previouslyLinked
          ? "A previously withdrawn required association needs explicit review before relinking."
          : "Required remediation work has no active evidence association.",
        Math.max(score, 50),
        {
          caseKey: row.caseKey, workItemId,
          executable: false,
          blockedBy: previouslyLinked ? ["REVIEW_WITHDRAWAL_HISTORY"] : [],
        },
      ));
    }
    if (row.activeWorkItemIds.length === 0 &&
        row.missingWorkItemIds.length === 0 && row.covered && !row.passing) {
      result.push(candidate(
        "CREATE_WORK_ASSIGNMENT", ["NO_ACTIVE_WORK"],
        "Coverage requires remediation work but no active association is available.",
        Math.max(score, 50), { caseKey: row.caseKey },
      ));
    }
  }
  return result;
}
function fromAuditFindings(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationCandidate[] {
  return portfolio.findings.filter(x => x.source === "AUDIT").map(item => {
    const severe = item.severity === "ERROR";
    const score = Math.max(
      item.caseKey ? caseRisk(risk, item.caseKey) : 0,
      item.workItemId ? workRisk(risk, item.workItemId) : 0,
      severe ? 75 : 25,
    );
    return candidate(
      severe ? "REVIEW_AUDIT_ERROR" : "REVIEW_AUDIT_WARNING",
      [item.code], item.explanation, score,
      {
        caseKey: item.caseKey, workItemId: item.workItemId,
        auditId: item.auditId, severe,
      },
    );
  });
}
function fromUncoveredCases(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationCandidate[] {
  return portfolio.cases.filter(x => !x.covered).map(row =>
    candidate(
      "REVIEW_UNCOVERED_CASE", ["UNCOVERED_CASE"],
      "This case has no evidence coverage policy; review whether it must be governed.",
      Math.max(25, caseRisk(risk, row.caseKey)),
      { caseKey: row.caseKey },
    ));
}
function fromUnreferencedWork(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationCandidate[] {
  return portfolio.workItems.filter(x => x.coverageDependencies === 0).map(row =>
    candidate(
      "REVIEW_UNREFERENCED_WORK", ["UNREFERENCED_WORK"],
      "This work item is not explicitly required by any coverage policy.",
      Math.max(25, workRisk(risk, row.workItemId)),
      { workItemId: row.workItemId },
    ));
}
function fromSharedDependencies(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationCandidate[] {
  return portfolio.workItems.filter(x =>
    x.singlePointOfFailure || x.coverageDependencies > 1).map(row =>
    candidate(
      "REVIEW_SHARED_DEPENDENCY",
      [
        ...(row.singlePointOfFailure ? ["SINGLE_POINT_OF_FAILURE"] : []),
        ...(row.coverageDependencies > 1 ? ["SHARED_WORK_DEPENDENCY"] : []),
      ],
      "Review resilience and ownership of a remediation work dependency.",
      Math.max(25, workRisk(risk, row.workItemId)),
      { workItemId: row.workItemId, dependencies: row.requiredByCaseKeys },
    ));
}
function fromWithdrawnOnlyCases(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationCandidate[] {
  return portfolio.cases.filter(x =>
    x.activeAssociations === 0 && x.withdrawnAssociations > 0).map(row =>
    candidate(
      "REVIEW_WITHDRAWN_ONLY_CASE", ["WITHDRAWN_ONLY"],
      "The case retains audit history but has no active work evidence.",
      Math.max(50, caseRisk(risk, row.caseKey)),
      { caseKey: row.caseKey },
    ));
}
function fromPolicyConflicts(
  portfolio: IntegrityEvidencePortfolio,
): IntegrityRemediationCandidate[] {
  return portfolio.policies.filter(x => !x.passed && x.failingRules === 0).map(row =>
    candidate(
      "REVIEW_POLICY_CONFLICT", ["POLICY_LEVEL_FAILURE"],
      "Policy-level constraints fail despite individually passing case rules.",
      50, { policyIndex: row.policyIndex },
    ));
}
function mergeCandidates(items: IntegrityRemediationCandidate[]) {
  const result = new Map<string, IntegrityRemediationCandidate>();
  for (const item of items) {
    const existing = result.get(item.id);
    if (!existing) {
      result.set(item.id, item);
      continue;
    }
    const stronger = priorities.indexOf(item.priority) <
      priorities.indexOf(existing.priority) ? item.priority : existing.priority;
    result.set(item.id, {
      ...existing, priority: stronger,
      reasonCodes: unique([...existing.reasonCodes, ...item.reasonCodes]),
      dependencies: unique([...existing.dependencies, ...item.dependencies]),
      blockedBy: unique([...existing.blockedBy, ...item.blockedBy]),
      estimatedRiskReduction: Math.max(
        existing.estimatedRiskReduction, item.estimatedRiskReduction),
      executable: existing.executable && item.executable,
    });
  }
  return [...result.values()].sort((a, b) =>
    priorities.indexOf(a.priority) - priorities.indexOf(b.priority) ||
    b.estimatedRiskReduction - a.estimatedRiskReduction ||
    compare(a.id, b.id));
}
export function buildIntegrityRemediationPlan(
  portfolio: IntegrityEvidencePortfolio,
  risk: IntegrityPortfolioRiskReport,
): IntegrityRemediationPlan {
  if (portfolio.captureId !== risk.captureId)
    throw new WorkInputError("INVALID", "Risk and portfolio captures differ.");
  const candidates = mergeCandidates([
    ...fromMissingWork(portfolio, risk),
    ...fromAuditFindings(portfolio, risk),
    ...fromUncoveredCases(portfolio, risk),
    ...fromUnreferencedWork(portfolio, risk),
    ...fromSharedDependencies(portfolio, risk),
    ...fromWithdrawnOnlyCases(portfolio, risk),
    ...fromPolicyConflicts(portfolio),
  ]);
  return {
    schemaVersion: 1, captureId: portfolio.captureId,
    generatedAt: portfolio.evaluatedAt,
    candidates,
    totals: {
      candidates: candidates.length,
      executable: candidates.filter(x => x.executable).length,
      advisory: candidates.filter(x => !x.executable).length,
      blocked: candidates.filter(x => x.blockedBy.length > 0).length,
      p0: candidates.filter(x => x.priority === "P0").length,
      p1: candidates.filter(x => x.priority === "P1").length,
      p2: candidates.filter(x => x.priority === "P2").length,
      p3: candidates.filter(x => x.priority === "P3").length,
      affectedCases: unique(candidates.flatMap(x => x.caseKey ? [x.caseKey] : [])).length,
      affectedWorkItems: unique(candidates.flatMap(x =>
        x.workItemId ? [x.workItemId] : [])).length,
      estimatedRiskReduction: candidates.reduce((sum, x) =>
        sum + x.estimatedRiskReduction, 0),
    },
  };
}
export function queryIntegrityRemediationPlan(
  plan: IntegrityRemediationPlan,
  query: IntegrityRemediationPlanQuery,
): IntegrityRemediationPlanPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid remediation pagination.");
  const selected = plan.candidates.filter(item =>
    (!query.priorities || query.priorities.includes(item.priority)) &&
    (!query.actions || query.actions.includes(item.action)) &&
    (!query.caseKeys || (item.caseKey !== null &&
      query.caseKeys.includes(item.caseKey))) &&
    (!query.workItemIds || (item.workItemId !== null &&
      query.workItemIds.includes(item.workItemId))) &&
    (!query.executableOnly || item.executable) &&
    (query.includeBlocked !== false || item.blockedBy.length === 0));
  return {
    captureId: plan.captureId, total: selected.length, offset, limit,
    hasMore: offset + limit < selected.length,
    candidates: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityRemediationPlans(
  before: IntegrityRemediationPlan,
  after: IntegrityRemediationPlan,
): IntegrityRemediationPlanDelta {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Cannot compare remediation captures.");
  const old = new Map(before.candidates.map(x => [x.id, x]));
  const current = new Map(after.candidates.map(x => [x.id, x]));
  const added = after.candidates.filter(x => !old.has(x.id));
  const removed = before.candidates.filter(x => !current.has(x.id));
  const reprioritized: IntegrityRemediationPlanDelta["reprioritized"] = [];
  const newlyExecutable: string[] = [];
  const newlyBlocked: string[] = [];
  let unchanged = 0;
  for (const [id, item] of current) {
    const previous = old.get(id);
    if (!previous) continue;
    if (item.priority !== previous.priority)
      reprioritized.push({ id, from: previous.priority, to: item.priority });
    if (item.executable && !previous.executable) newlyExecutable.push(id);
    if (!item.executable && previous.executable) newlyBlocked.push(id);
    if (JSON.stringify(item) === JSON.stringify(previous)) unchanged++;
  }
  return {
    captureId: before.captureId, added, removed,
    reprioritized: reprioritized.sort((a, b) => compare(a.id, b.id)),
    newlyExecutable: newlyExecutable.sort(compare),
    newlyBlocked: newlyBlocked.sort(compare), unchanged,
  };
}
export function planIntegrityRemediationFromEvents(
  input: IntegrityEvidencePortfolioInput,
  events: readonly IntegrityLinkHistoryEvent[],
  weights?: IntegrityPortfolioRiskWeights,
) {
  const portfolio = buildIntegrityEvidencePortfolio(input, events);
  const risk = analyzeIntegrityPortfolioRisk(portfolio, weights);
  const plan = buildIntegrityRemediationPlan(portfolio, risk);
  return { portfolio, risk, plan };
}
