import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationPlan, IntegrityRemediationCandidate,
  IntegrityRemediationPriority,
} from "./work-integrity-remediation-plan";

export type IntegrityRemediationGateRule = {
  id: string;
  kind:
    | "MAX_OPEN"
    | "MAX_URGENT"
    | "MAX_BLOCKED"
    | "MAX_ADVISORY"
    | "MAX_RISK_POINTS"
    | "REQUIRE_NO_P0"
    | "REQUIRE_NO_AUDIT_ERRORS"
    | "REQUIRE_NO_WITHDRAWAL_RELINKS"
    | "REQUIRE_ACTION_LIMIT"
    | "REQUIRE_CASE_LIMIT"
    | "REQUIRE_WORK_LIMIT";
  threshold?: number;
  action?: IntegrityRemediationCandidate["action"];
  caseKey?: string;
  workItemId?: string;
  severity: "ERROR" | "WARNING";
};
export type IntegrityRemediationGatePolicy = {
  schemaVersion: 1;
  rules: IntegrityRemediationGateRule[];
  failOnWarnings: boolean;
};
export type IntegrityRemediationGateViolation = {
  ruleId: string;
  kind: IntegrityRemediationGateRule["kind"];
  severity: "ERROR" | "WARNING";
  observed: number;
  allowed: number;
  candidateIds: string[];
  explanation: string;
};
export type IntegrityRemediationGateReport = {
  schemaVersion: 1;
  captureId: string;
  passed: boolean;
  errorCount: number;
  warningCount: number;
  evaluatedRules: number;
  passingRules: number;
  failingRules: number;
  violations: IntegrityRemediationGateViolation[];
  byPriority: Record<IntegrityRemediationPriority, number>;
  byAction: Record<string, number>;
};
export type IntegrityRemediationGateDelta = {
  captureId: string;
  beforePassed: boolean;
  afterPassed: boolean;
  introduced: IntegrityRemediationGateViolation[];
  resolved: IntegrityRemediationGateViolation[];
  retained: IntegrityRemediationGateViolation[];
  newlyAffectedCandidates: string[];
  noLongerAffectedCandidates: string[];
};
const kinds: IntegrityRemediationGateRule["kind"][] = [
  "MAX_OPEN", "MAX_URGENT", "MAX_BLOCKED", "MAX_ADVISORY",
  "MAX_RISK_POINTS", "REQUIRE_NO_P0", "REQUIRE_NO_AUDIT_ERRORS",
  "REQUIRE_NO_WITHDRAWAL_RELINKS", "REQUIRE_ACTION_LIMIT",
  "REQUIRE_CASE_LIMIT", "REQUIRE_WORK_LIMIT",
];
const thresholdKinds = new Set<IntegrityRemediationGateRule["kind"]>([
  "MAX_OPEN", "MAX_URGENT", "MAX_BLOCKED", "MAX_ADVISORY",
  "MAX_RISK_POINTS", "REQUIRE_ACTION_LIMIT", "REQUIRE_CASE_LIMIT",
  "REQUIRE_WORK_LIMIT",
]);
function object(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function id(value: unknown, label: string) {
  if (typeof value !== "string" || !value ||
      value.length > 1500 || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function integer(value: unknown, label: string) {
  if (!Number.isSafeInteger(value) || (value as number) < 0 ||
      (value as number) > 10000000)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
export function parseIntegrityRemediationGatePolicy(
  value: unknown,
): IntegrityRemediationGatePolicy {
  const raw = object(value, "remediation gate policy");
  if (Object.keys(raw).some(x => ![
    "schemaVersion", "rules", "failOnWarnings",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown gate policy field.");
  if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1)
    throw new WorkInputError("INVALID", "Unsupported gate policy version.");
  if (!Array.isArray(raw.rules) || raw.rules.length < 1 ||
      raw.rules.length > 100)
    throw new WorkInputError("INVALID", "Invalid gate rules.");
  if (raw.failOnWarnings !== undefined &&
      typeof raw.failOnWarnings !== "boolean")
    throw new WorkInputError("INVALID", "Invalid gate warning behavior.");
  const seen = new Set<string>();
  const rules: IntegrityRemediationGateRule[] = [];
  for (const entry of raw.rules) {
    const row = object(entry, "gate rule");
    if (Object.keys(row).some(x => ![
      "id", "kind", "threshold", "action", "caseKey",
      "workItemId", "severity",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown gate rule field.");
    const key = id(row.id, "gate rule ID");
    if (seen.has(key))
      throw new WorkInputError("INVALID", "Duplicate gate rule ID.");
    seen.add(key);
    if (!kinds.includes(row.kind as IntegrityRemediationGateRule["kind"]))
      throw new WorkInputError("INVALID", "Unknown gate rule kind.");
    const kind = row.kind as IntegrityRemediationGateRule["kind"];
    const severity = row.severity ?? "ERROR";
    if (severity !== "ERROR" && severity !== "WARNING")
      throw new WorkInputError("INVALID", "Invalid gate severity.");
    const needsThreshold = thresholdKinds.has(kind);
    if (needsThreshold && row.threshold === undefined)
      throw new WorkInputError("INVALID", "Gate threshold required.");
    if (!needsThreshold && row.threshold !== undefined)
      throw new WorkInputError("INVALID", "Unexpected gate threshold.");
    if (kind === "REQUIRE_ACTION_LIMIT" && row.action === undefined)
      throw new WorkInputError("INVALID", "Action limit requires action.");
    if (kind === "REQUIRE_CASE_LIMIT" && row.caseKey === undefined)
      throw new WorkInputError("INVALID", "Case limit requires case.");
    if (kind === "REQUIRE_WORK_LIMIT" && row.workItemId === undefined)
      throw new WorkInputError("INVALID", "Work limit requires work ID.");
    if (row.action !== undefined && kind !== "REQUIRE_ACTION_LIMIT")
      throw new WorkInputError("INVALID", "Unexpected gate action.");
    if (row.caseKey !== undefined && kind !== "REQUIRE_CASE_LIMIT")
      throw new WorkInputError("INVALID", "Unexpected gate case.");
    if (row.workItemId !== undefined && kind !== "REQUIRE_WORK_LIMIT")
      throw new WorkInputError("INVALID", "Unexpected gate work ID.");
    rules.push({
      id: key, kind, severity,
      ...(needsThreshold ? { threshold: integer(row.threshold, "gate threshold") } : {}),
      ...(row.action !== undefined ? {
        action: id(row.action, "gate action") as IntegrityRemediationCandidate["action"],
      } : {}),
      ...(row.caseKey !== undefined ? { caseKey: id(row.caseKey, "gate case") } : {}),
      ...(row.workItemId !== undefined ? {
        workItemId: id(row.workItemId, "gate work ID"),
      } : {}),
    });
  }
  return {
    schemaVersion: 1, rules,
    failOnWarnings: raw.failOnWarnings === true,
  };
}
function selected(
  rule: IntegrityRemediationGateRule,
  candidates: readonly IntegrityRemediationCandidate[],
): IntegrityRemediationCandidate[] {
  switch (rule.kind) {
    case "MAX_OPEN": return [...candidates];
    case "MAX_URGENT": return candidates.filter(x =>
      x.priority === "P0" || x.priority === "P1");
    case "MAX_BLOCKED": return candidates.filter(x => x.blockedBy.length > 0);
    case "MAX_ADVISORY": return candidates.filter(x => !x.executable);
    case "MAX_RISK_POINTS": return [...candidates];
    case "REQUIRE_NO_P0": return candidates.filter(x => x.priority === "P0");
    case "REQUIRE_NO_AUDIT_ERRORS": return candidates.filter(x =>
      x.action === "REVIEW_AUDIT_ERROR");
    case "REQUIRE_NO_WITHDRAWAL_RELINKS": return candidates.filter(x =>
      x.action === "RELINK_WITHDRAWN_WORK");
    case "REQUIRE_ACTION_LIMIT": return candidates.filter(x =>
      x.action === rule.action);
    case "REQUIRE_CASE_LIMIT": return candidates.filter(x =>
      x.caseKey === rule.caseKey);
    case "REQUIRE_WORK_LIMIT": return candidates.filter(x =>
      x.workItemId === rule.workItemId);
  }
}
function observed(
  rule: IntegrityRemediationGateRule,
  candidates: readonly IntegrityRemediationCandidate[],
) {
  return rule.kind === "MAX_RISK_POINTS"
    ? candidates.reduce((sum, x) => sum + x.estimatedRiskReduction, 0)
    : candidates.length;
}
function explanation(rule: IntegrityRemediationGateRule, observed: number,
  allowed: number) {
  return rule.id + ": observed " + observed +
    " exceeds allowed " + allowed + " for " + rule.kind + ".";
}
export function evaluateIntegrityRemediationGate(
  plan: IntegrityRemediationPlan,
  policy: IntegrityRemediationGatePolicy,
): IntegrityRemediationGateReport {
  const violations: IntegrityRemediationGateViolation[] = [];
  const byPriority: Record<IntegrityRemediationPriority, number> = {
    P0: 0, P1: 0, P2: 0, P3: 0,
  };
  const byAction: Record<string, number> = {};
  for (const candidate of plan.candidates) {
    byPriority[candidate.priority]++;
    byAction[candidate.action] = (byAction[candidate.action] ?? 0) + 1;
  }
  for (const rule of policy.rules) {
    const matches = selected(rule, plan.candidates);
    const value = observed(rule, matches);
    const allowed = rule.threshold ?? 0;
    if (value <= allowed) continue;
    violations.push({
      ruleId: rule.id, kind: rule.kind,
      severity: rule.severity, observed: value, allowed,
      candidateIds: matches.map(x => x.id).sort(),
      explanation: explanation(rule, value, allowed),
    });
  }
  const errorCount = violations.filter(x => x.severity === "ERROR").length;
  const warningCount = violations.length - errorCount;
  return {
    schemaVersion: 1, captureId: plan.captureId,
    passed: errorCount === 0 && (!policy.failOnWarnings || warningCount === 0),
    errorCount, warningCount, evaluatedRules: policy.rules.length,
    passingRules: policy.rules.length - violations.length,
    failingRules: violations.length,
    violations, byPriority, byAction,
  };
}
export function compareIntegrityRemediationGates(
  before: IntegrityRemediationGateReport,
  after: IntegrityRemediationGateReport,
): IntegrityRemediationGateDelta {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Gate reports belong to different captures.");
  const old = new Map(before.violations.map(x => [x.ruleId, x]));
  const current = new Map(after.violations.map(x => [x.ruleId, x]));
  const introduced = after.violations.filter(x => !old.has(x.ruleId));
  const resolved = before.violations.filter(x => !current.has(x.ruleId));
  const retained = after.violations.filter(x => old.has(x.ruleId));
  const beforeAffected = new Set(before.violations.flatMap(x => x.candidateIds));
  const afterAffected = new Set(after.violations.flatMap(x => x.candidateIds));
  return {
    captureId: before.captureId,
    beforePassed: before.passed, afterPassed: after.passed,
    introduced, resolved, retained,
    newlyAffectedCandidates: [...afterAffected].filter(x =>
      !beforeAffected.has(x)).sort(),
    noLongerAffectedCandidates: [...beforeAffected].filter(x =>
      !afterAffected.has(x)).sort(),
  };
}
