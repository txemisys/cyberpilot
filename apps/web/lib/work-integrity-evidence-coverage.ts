import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { reviewIntegrityLinks, type LinkReviewAssociation } from "./work-integrity-link-review";
import {
  buildIntegrityEvidenceGraph, type IntegrityEvidenceGraph,
} from "./work-integrity-evidence-graph";

export type IntegrityEvidenceCoverageRule = {
  id: string;
  caseKey: string;
  requiredWorkItemIds?: string[];
  minimumActiveWorkItems: number;
  maximumActiveWorkItems?: number;
  requireDistinctActors?: number;
  forbidWithdrawnOnly?: boolean;
};
export type IntegrityEvidenceCoveragePolicy = {
  captureId: string;
  rules: IntegrityEvidenceCoverageRule[];
  allowUnlistedCases?: boolean;
  requireAllActiveWorkReferenced?: boolean;
};
export type IntegrityEvidenceCoverageFindingCode =
  | "MISSING_CASE" | "INSUFFICIENT_ACTIVE_WORK"
  | "EXCESS_ACTIVE_WORK" | "MISSING_REQUIRED_WORK"
  | "INSUFFICIENT_DISTINCT_ACTORS" | "WITHDRAWN_ONLY"
  | "UNLISTED_ACTIVE_CASE" | "UNREFERENCED_ACTIVE_WORK";
export type IntegrityEvidenceCoverageFinding = {
  code: IntegrityEvidenceCoverageFindingCode;
  ruleId: string | null;
  caseKey: string | null;
  workItemId: string | null;
  expected: number | null;
  observed: number | null;
  explanation: string;
};
export type IntegrityEvidenceCoverageCase = {
  caseKey: string;
  ruleId: string;
  required: number;
  observed: number;
  distinctActors: number;
  activeWorkItemIds: string[];
  withdrawnWorkItemIds: string[];
  missingWorkItemIds: string[];
  passed: boolean;
};
export type IntegrityEvidenceCoverageReport = {
  schemaVersion: 1;
  captureId: string;
  passed: boolean;
  evaluatedRules: number;
  passingRules: number;
  failingRules: number;
  activeCases: number;
  activeWorkItems: number;
  cases: IntegrityEvidenceCoverageCase[];
  findings: IntegrityEvidenceCoverageFinding[];
};
export type IntegrityEvidenceCoverageDelta = {
  captureId: string;
  beforePassed: boolean;
  afterPassed: boolean;
  improvedCases: string[];
  regressedCases: string[];
  unchangedCases: string[];
  introducedFindings: IntegrityEvidenceCoverageFinding[];
  resolvedFindings: IntegrityEvidenceCoverageFinding[];
};
function integer(value: unknown, label: string, minimum: number, maximum: number) {
  if (!Number.isSafeInteger(value) || (value as number) < minimum ||
      (value as number) > maximum)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
function identity(value: unknown, label: string) {
  if (typeof value !== "string" || !value || value.length > 1500 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function array(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length > 1000)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value.map(x => identity(x, label)))];
}
function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function allowed(value: Record<string, unknown>, fields: readonly string[]) {
  if (Object.keys(value).some(key => !fields.includes(key)))
    throw new WorkInputError("INVALID", "Unknown coverage field.");
}
export function parseIntegrityEvidenceCoveragePolicy(
  value: unknown,
): IntegrityEvidenceCoveragePolicy {
  const raw = record(value, "coverage policy");
  allowed(raw, ["captureId", "rules", "allowUnlistedCases", "requireAllActiveWorkReferenced"]);
  const captureId = identity(raw.captureId, "capture ID");
  if (!/^[a-zA-Z0-9_-]{5,100}$/.test(captureId))
    throw new WorkInputError("INVALID", "Invalid capture identifier.");
  if (!Array.isArray(raw.rules) || raw.rules.length < 1 || raw.rules.length > 500)
    throw new WorkInputError("INVALID", "Coverage policy requires 1–500 rules.");
  for (const field of ["allowUnlistedCases", "requireAllActiveWorkReferenced"]) {
    if (raw[field] !== undefined && typeof raw[field] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid " + field);
  }
  const ids = new Set<string>();
  const cases = new Set<string>();
  const rules = raw.rules.map(value => {
    const rule = record(value, "coverage rule");
    allowed(rule, [
      "id", "caseKey", "requiredWorkItemIds", "minimumActiveWorkItems",
      "maximumActiveWorkItems", "requireDistinctActors", "forbidWithdrawnOnly",
    ]);
    const id = identity(rule.id, "rule ID");
    const caseKey = identity(rule.caseKey, "case key");
    if (ids.has(id) || cases.has(caseKey))
      throw new WorkInputError("INVALID", "Duplicate rule or case identity.");
    ids.add(id); cases.add(caseKey);
    const minimumActiveWorkItems = integer(
      rule.minimumActiveWorkItems, "minimum active work", 0, 100000);
    const maximumActiveWorkItems = rule.maximumActiveWorkItems === undefined
      ? undefined : integer(rule.maximumActiveWorkItems, "maximum active work", 0, 100000);
    if (maximumActiveWorkItems !== undefined &&
        maximumActiveWorkItems < minimumActiveWorkItems)
      throw new WorkInputError("INVALID", "Maximum work count is below minimum.");
    const requireDistinctActors = rule.requireDistinctActors === undefined
      ? undefined : integer(rule.requireDistinctActors, "distinct actors", 0, 100000);
    if (rule.forbidWithdrawnOnly !== undefined &&
        typeof rule.forbidWithdrawnOnly !== "boolean")
      throw new WorkInputError("INVALID", "Invalid withdrawn-only flag.");
    return {
      id, caseKey, minimumActiveWorkItems,
      ...(maximumActiveWorkItems === undefined ? {} : { maximumActiveWorkItems }),
      ...(requireDistinctActors === undefined ? {} : { requireDistinctActors }),
      ...(rule.requiredWorkItemIds === undefined ? {} :
        { requiredWorkItemIds: array(rule.requiredWorkItemIds, "required work items") }),
      ...(rule.forbidWithdrawnOnly === undefined ? {} :
        { forbidWithdrawnOnly: rule.forbidWithdrawnOnly as boolean }),
    };
  });
  return {
    captureId, rules,
    allowUnlistedCases: raw.allowUnlistedCases !== false,
    requireAllActiveWorkReferenced: raw.requireAllActiveWorkReferenced === true,
  };
}
function finding(
  code: IntegrityEvidenceCoverageFindingCode,
  explanation: string,
  ruleId: string | null = null,
  caseKey: string | null = null,
  workItemId: string | null = null,
  expected: number | null = null,
  observed: number | null = null,
): IntegrityEvidenceCoverageFinding {
  return { code, ruleId, caseKey, workItemId, expected, observed, explanation };
}
function unique(values: readonly string[]) {
  return [...new Set(values)].sort();
}
function activeForCase(
  associations: readonly LinkReviewAssociation[], caseKey: string,
) {
  return associations.filter(x => x.caseKey === caseKey && x.state === "ACTIVE");
}
export function evaluateIntegrityEvidenceCoverage(
  graph: IntegrityEvidenceGraph,
  associations: readonly LinkReviewAssociation[],
  policy: IntegrityEvidenceCoveragePolicy,
): IntegrityEvidenceCoverageReport {
  if (graph.captureId !== policy.captureId ||
      associations.some(x => x.captureId !== policy.captureId))
    throw new WorkInputError("INVALID", "Coverage capture mismatch.");
  const findings: IntegrityEvidenceCoverageFinding[] = [];
  const cases: IntegrityEvidenceCoverageCase[] = [];
  const listed = new Set(policy.rules.map(x => x.caseKey));
  const activeAssociations = associations.filter(x => x.state === "ACTIVE");
  for (const rule of policy.rules) {
    const all = associations.filter(x => x.caseKey === rule.caseKey);
    const active = activeForCase(associations, rule.caseKey);
    const activeWorkItemIds = unique(active.map(x => x.workItemId));
    const withdrawnWorkItemIds = unique(all.filter(x => x.state === "WITHDRAWN")
      .map(x => x.workItemId));
    const actors = unique(active.flatMap(x =>
      x.createdBy === null ? [] : [x.createdBy]));
    const missingWorkItemIds = (rule.requiredWorkItemIds ?? [])
      .filter(id => !activeWorkItemIds.includes(id)).sort();
    const previous = findings.length;
    if (all.length === 0)
      findings.push(finding("MISSING_CASE", "Case has no historical association.",
        rule.id, rule.caseKey));
    if (activeWorkItemIds.length < rule.minimumActiveWorkItems)
      findings.push(finding("INSUFFICIENT_ACTIVE_WORK",
        "Case has fewer distinct active work items than required.",
        rule.id, rule.caseKey, null,
        rule.minimumActiveWorkItems, activeWorkItemIds.length));
    if (rule.maximumActiveWorkItems !== undefined &&
        activeWorkItemIds.length > rule.maximumActiveWorkItems)
      findings.push(finding("EXCESS_ACTIVE_WORK",
        "Case has more distinct active work items than allowed.",
        rule.id, rule.caseKey, null,
        rule.maximumActiveWorkItems, activeWorkItemIds.length));
    for (const workItemId of missingWorkItemIds)
      findings.push(finding("MISSING_REQUIRED_WORK",
        "Required work item is not actively associated.",
        rule.id, rule.caseKey, workItemId));
    if (rule.requireDistinctActors !== undefined &&
        actors.length < rule.requireDistinctActors)
      findings.push(finding("INSUFFICIENT_DISTINCT_ACTORS",
        "Case lacks the configured number of distinct linking actors.",
        rule.id, rule.caseKey, null, rule.requireDistinctActors, actors.length));
    if (rule.forbidWithdrawnOnly && all.length > 0 && active.length === 0)
      findings.push(finding("WITHDRAWN_ONLY",
        "Case has only withdrawn historical associations.",
        rule.id, rule.caseKey));
    cases.push({
      caseKey: rule.caseKey, ruleId: rule.id,
      required: rule.minimumActiveWorkItems, observed: activeWorkItemIds.length,
      distinctActors: actors.length, activeWorkItemIds,
      withdrawnWorkItemIds, missingWorkItemIds,
      passed: findings.length === previous,
    });
  }
  if (policy.allowUnlistedCases === false) {
    for (const caseKey of unique(activeAssociations.map(x => x.caseKey))) {
      if (!listed.has(caseKey))
        findings.push(finding("UNLISTED_ACTIVE_CASE",
          "An active association references a case outside the coverage policy.",
          null, caseKey));
    }
  }
  if (policy.requireAllActiveWorkReferenced) {
    const required = new Set(policy.rules.flatMap(x => x.requiredWorkItemIds ?? []));
    for (const workItemId of unique(activeAssociations.map(x => x.workItemId))) {
      if (!required.has(workItemId))
        findings.push(finding("UNREFERENCED_ACTIVE_WORK",
          "Active work item is not explicitly required by any coverage rule.",
          null, null, workItemId));
    }
  }
  findings.sort((a, b) =>
    a.code.localeCompare(b.code) ||
    (a.caseKey ?? "").localeCompare(b.caseKey ?? "") ||
    (a.workItemId ?? "").localeCompare(b.workItemId ?? ""));
  const passingRules = cases.filter(x => x.passed).length;
  return {
    schemaVersion: 1, captureId: policy.captureId,
    passed: findings.length === 0,
    evaluatedRules: policy.rules.length, passingRules,
    failingRules: cases.length - passingRules,
    activeCases: unique(activeAssociations.map(x => x.caseKey)).length,
    activeWorkItems: unique(activeAssociations.map(x => x.workItemId)).length,
    cases, findings,
  };
}
function findingIdentity(item: IntegrityEvidenceCoverageFinding) {
  return JSON.stringify([item.code, item.ruleId, item.caseKey, item.workItemId]);
}
export function compareIntegrityEvidenceCoverage(
  before: IntegrityEvidenceCoverageReport,
  after: IntegrityEvidenceCoverageReport,
): IntegrityEvidenceCoverageDelta {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Cannot compare coverage for different captures.");
  const old = new Map(before.cases.map(x => [x.caseKey, x]));
  const current = new Map(after.cases.map(x => [x.caseKey, x]));
  const improvedCases: string[] = [];
  const regressedCases: string[] = [];
  const unchangedCases: string[] = [];
  for (const [caseKey, row] of current) {
    const previous = old.get(caseKey);
    if (!previous || previous.passed === row.passed) unchangedCases.push(caseKey);
    else if (row.passed) improvedCases.push(caseKey);
    else regressedCases.push(caseKey);
  }
  const previousFindings = new Map(before.findings.map(x => [findingIdentity(x), x]));
  const nextFindings = new Map(after.findings.map(x => [findingIdentity(x), x]));
  return {
    captureId: before.captureId, beforePassed: before.passed, afterPassed: after.passed,
    improvedCases: improvedCases.sort(), regressedCases: regressedCases.sort(),
    unchangedCases: unchangedCases.sort(),
    introducedFindings: [...nextFindings].filter(([id]) =>
      !previousFindings.has(id)).map(([, x]) => x),
    resolvedFindings: [...previousFindings].filter(([id]) =>
      !nextFindings.has(id)).map(([, x]) => x),
  };
}
export function evaluateIntegrityEvidenceCoverageEvents(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  policy: IntegrityEvidenceCoveragePolicy,
): IntegrityEvidenceCoverageReport {
  const report = reviewIntegrityLinks(captureId, events);
  const graph = buildIntegrityEvidenceGraph(captureId, report.associations);
  return evaluateIntegrityEvidenceCoverage(graph, report.associations, policy);
}
