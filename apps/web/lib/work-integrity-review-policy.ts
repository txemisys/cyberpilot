import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, type LinkReviewReport,
  type LinkReviewAssociation, type LinkReviewFinding,
} from "./work-integrity-link-review";

export type IntegrityReviewRuleId =
  | "ORPHAN_WITHDRAWAL" | "DUPLICATE_WITHDRAWAL"
  | "MISMATCHED_WITHDRAWAL" | "WITHDRAWAL_BEFORE_LINK"
  | "DUPLICATE_AUDIT_ID" | "INVALID_TIMESTAMP"
  | "REPEATED_ACTIVE_ASSOCIATION"
  | "UNEXPECTED_CASE" | "UNEXPECTED_WORK_ITEM"
  | "EXCESS_ACTIVE_ASSOCIATIONS" | "STALE_ACTIVE_ASSOCIATION";
export type IntegrityReviewPolicy = {
  allowedCaseKeys?: string[];
  allowedWorkItemIds?: string[];
  maxActivePerCase?: number;
  maxActivePerWorkItem?: number;
  maxAgeDays?: number;
  asOf: string;
  ignoredFindingCodes?: string[];
};
export type IntegrityPolicyViolation = {
  ruleId: IntegrityReviewRuleId;
  severity: "ERROR" | "WARNING";
  auditId: string | null;
  caseKey: string | null;
  workItemId: string | null;
  explanation: string;
};
export type IntegrityPolicyEvaluation = {
  schemaVersion: 1;
  captureId: string;
  asOf: string;
  passed: boolean;
  evaluatedAssociations: number;
  violations: IntegrityPolicyViolation[];
  byRule: Partial<Record<IntegrityReviewRuleId, number>>;
  bySeverity: { errors: number; warnings: number };
};
export type IntegrityPolicyComparison = {
  introduced: IntegrityPolicyViolation[];
  resolved: IntegrityPolicyViolation[];
  retained: IntegrityPolicyViolation[];
};
function timestamp(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function strings(value: unknown, label: string, max: number): string[] {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x || x.length > 1500))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function optionalCount(value: unknown, label: string, max: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
export function parseIntegrityReviewPolicy(value: unknown): IntegrityReviewPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Review policy must be an object.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => ![
    "asOf", "allowedCaseKeys", "allowedWorkItemIds",
    "maxActivePerCase", "maxActivePerWorkItem", "maxAgeDays",
    "ignoredFindingCodes",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown review policy field.");
  if (!timestamp(raw.asOf))
    throw new WorkInputError("INVALID", "Invalid policy evaluation timestamp.");
  const policy: IntegrityReviewPolicy = { asOf: raw.asOf };
  if (raw.allowedCaseKeys !== undefined)
    policy.allowedCaseKeys = strings(raw.allowedCaseKeys, "allowed cases", 10000);
  if (raw.allowedWorkItemIds !== undefined)
    policy.allowedWorkItemIds = strings(raw.allowedWorkItemIds, "allowed work items", 10000);
  if (raw.ignoredFindingCodes !== undefined)
    policy.ignoredFindingCodes = strings(raw.ignoredFindingCodes, "ignored codes", 50);
  if (raw.maxActivePerCase !== undefined)
    policy.maxActivePerCase = optionalCount(raw.maxActivePerCase, "case limit", 100000);
  if (raw.maxActivePerWorkItem !== undefined)
    policy.maxActivePerWorkItem = optionalCount(raw.maxActivePerWorkItem, "work limit", 100000);
  if (raw.maxAgeDays !== undefined)
    policy.maxAgeDays = optionalCount(raw.maxAgeDays, "maximum age", 36500);
  return policy;
}
function violation(
  ruleId: IntegrityReviewRuleId, explanation: string,
  association?: LinkReviewAssociation,
  severity: "ERROR" | "WARNING" = "WARNING",
): IntegrityPolicyViolation {
  return {
    ruleId, severity,
    auditId: association?.auditId ?? null,
    caseKey: association?.caseKey ?? null,
    workItemId: association?.workItemId ?? null,
    explanation,
  };
}
function fromFinding(finding: LinkReviewFinding): IntegrityPolicyViolation {
  return {
    ruleId: finding.code as IntegrityReviewRuleId,
    severity: finding.severity,
    auditId: finding.auditId, caseKey: finding.caseKey,
    workItemId: finding.workItemId, explanation: finding.explanation,
  };
}
export function evaluateIntegrityReviewPolicy(
  report: LinkReviewReport, policy: IntegrityReviewPolicy,
): IntegrityPolicyEvaluation {
  if (!timestamp(policy.asOf))
    throw new WorkInputError("INVALID", "Invalid evaluation time.");
  const violations: IntegrityPolicyViolation[] = [];
  const ignored = new Set(policy.ignoredFindingCodes ?? []);
  for (const finding of report.findings) {
    if (!ignored.has(finding.code)) violations.push(fromFinding(finding));
  }
  const allowedCases = policy.allowedCaseKeys
    ? new Set(policy.allowedCaseKeys) : null;
  const allowedWork = policy.allowedWorkItemIds
    ? new Set(policy.allowedWorkItemIds) : null;
  const caseCounts = new Map<string, number>();
  const workCounts = new Map<string, number>();
  for (const association of report.associations) {
    if (association.createdAt > policy.asOf) continue;
    if (association.state !== "ACTIVE" &&
        (!association.withdrawnAt || association.withdrawnAt <= policy.asOf))
      continue;
    if (allowedCases && !allowedCases.has(association.caseKey)) {
      violations.push(violation("UNEXPECTED_CASE",
        "Association refers to a case outside the approved set.", association, "ERROR"));
    }
    if (allowedWork && !allowedWork.has(association.workItemId)) {
      violations.push(violation("UNEXPECTED_WORK_ITEM",
        "Association refers to work outside the approved set.", association, "ERROR"));
    }
    caseCounts.set(association.caseKey, (caseCounts.get(association.caseKey) ?? 0) + 1);
    workCounts.set(association.workItemId, (workCounts.get(association.workItemId) ?? 0) + 1);
    if (policy.maxAgeDays !== undefined) {
      const age = Date.parse(policy.asOf) - Date.parse(association.createdAt);
      if (age > policy.maxAgeDays * 86400000) {
        violations.push(violation("STALE_ACTIVE_ASSOCIATION",
          "Association exceeds the configured maximum age.", association));
      }
    }
  }
  for (const [caseKey, count] of caseCounts) {
    if (policy.maxActivePerCase !== undefined && count > policy.maxActivePerCase)
      violations.push({
        ruleId: "EXCESS_ACTIVE_ASSOCIATIONS", severity: "WARNING",
        auditId: null, caseKey, workItemId: null,
        explanation: "Active associations for case exceed configured limit.",
      });
  }
  for (const [workItemId, count] of workCounts) {
    if (policy.maxActivePerWorkItem !== undefined && count > policy.maxActivePerWorkItem)
      violations.push({
        ruleId: "EXCESS_ACTIVE_ASSOCIATIONS", severity: "WARNING",
        auditId: null, caseKey: null, workItemId,
        explanation: "Active associations for work item exceed configured limit.",
      });
  }
  violations.sort((a, b) =>
    a.ruleId.localeCompare(b.ruleId) ||
    (a.auditId ?? "").localeCompare(b.auditId ?? "") ||
    (a.caseKey ?? "").localeCompare(b.caseKey ?? "") ||
    (a.workItemId ?? "").localeCompare(b.workItemId ?? ""));
  const byRule: Partial<Record<IntegrityReviewRuleId, number>> = {};
  for (const item of violations)
    byRule[item.ruleId] = (byRule[item.ruleId] ?? 0) + 1;
  const errors = violations.filter(x => x.severity === "ERROR").length;
  const warnings = violations.length - errors;
  return {
    schemaVersion: 1, captureId: report.captureId, asOf: policy.asOf,
    passed: violations.length === 0,
    evaluatedAssociations: report.associations.length,
    violations, byRule, bySeverity: { errors, warnings },
  };
}
function identity(item: IntegrityPolicyViolation) {
  return JSON.stringify([
    item.ruleId, item.auditId, item.caseKey, item.workItemId,
  ]);
}
export function compareIntegrityPolicyEvaluations(
  before: IntegrityPolicyEvaluation, after: IntegrityPolicyEvaluation,
): IntegrityPolicyComparison {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Cannot compare different captures.");
  const old = new Map(before.violations.map(x => [identity(x), x]));
  const current = new Map(after.violations.map(x => [identity(x), x]));
  return {
    introduced: [...current].filter(([key]) => !old.has(key)).map(([, x]) => x),
    resolved: [...old].filter(([key]) => !current.has(key)).map(([, x]) => x),
    retained: [...current].filter(([key]) => old.has(key)).map(([, x]) => x),
  };
}
export function evaluateIntegrityEvents(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityReviewPolicy,
): IntegrityPolicyEvaluation {
  const visible = events.filter(x => x.occurredAt <= policy.asOf);
  return evaluateIntegrityReviewPolicy(reviewIntegrityLinks(captureId, visible), policy);
}
