import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityEvidencePortfolio, IntegrityEvidencePortfolioCase,
  IntegrityEvidencePortfolioWork, IntegrityEvidencePortfolioFinding,
} from "./work-integrity-evidence-portfolio";

export type IntegrityPortfolioRiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type IntegrityPortfolioRiskFactor = {
  code: string;
  points: number;
  explanation: string;
};
export type IntegrityPortfolioCaseRisk = {
  caseKey: string;
  score: number;
  level: IntegrityPortfolioRiskLevel;
  factors: IntegrityPortfolioRiskFactor[];
  activeWorkItems: number;
  missingRequiredWorkItems: number;
  covered: boolean;
  passing: boolean;
};
export type IntegrityPortfolioWorkRisk = {
  workItemId: string;
  score: number;
  level: IntegrityPortfolioRiskLevel;
  factors: IntegrityPortfolioRiskFactor[];
  activeCases: number;
  requiredByCases: number;
  singlePointOfFailure: boolean;
};
export type IntegrityPortfolioRiskReport = {
  schemaVersion: 1;
  captureId: string;
  cases: IntegrityPortfolioCaseRisk[];
  workItems: IntegrityPortfolioWorkRisk[];
  highestRiskCases: string[];
  highestRiskWorkItems: string[];
  distribution: Record<IntegrityPortfolioRiskLevel, number>;
  meanCaseRisk: number;
  meanWorkRisk: number;
  criticalFindings: number;
  totalFindings: number;
};
export type IntegrityPortfolioRiskWeights = {
  uncoveredCase: number;
  failingCase: number;
  missingRequiredWork: number;
  noActiveWork: number;
  withdrawnOnly: number;
  auditError: number;
  auditWarning: number;
  singlePointOfFailure: number;
  unreferencedWork: number;
  orphanedWork: number;
  multipleCaseDependencies: number;
};
export const DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS:
  Readonly<IntegrityPortfolioRiskWeights> = Object.freeze({
    uncoveredCase: 15,
    failingCase: 20,
    missingRequiredWork: 12,
    noActiveWork: 25,
    withdrawnOnly: 10,
    auditError: 20,
    auditWarning: 5,
    singlePointOfFailure: 25,
    unreferencedWork: 10,
    orphanedWork: 20,
    multipleCaseDependencies: 5,
  });
export type IntegrityPortfolioRiskQuery = {
  minimumScore?: number;
  levels?: IntegrityPortfolioRiskLevel[];
  caseKeys?: string[];
  workItemIds?: string[];
  offset?: number;
  limit?: number;
};
export type IntegrityPortfolioRiskPage = {
  captureId: string;
  totalCases: number;
  totalWorkItems: number;
  offset: number;
  limit: number;
  cases: IntegrityPortfolioCaseRisk[];
  workItems: IntegrityPortfolioWorkRisk[];
};
export type IntegrityPortfolioRiskDelta = {
  captureId: string;
  improvedCases: string[];
  regressedCases: string[];
  improvedWorkItems: string[];
  regressedWorkItems: string[];
  newCriticalCases: string[];
  resolvedCriticalCases: string[];
  newCriticalWorkItems: string[];
  resolvedCriticalWorkItems: string[];
  averageCaseScoreChange: number;
  averageWorkScoreChange: number;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected risk options object.");
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(value).some(key => !allowed.includes(key)))
    throw new WorkInputError("INVALID", "Unknown risk option.");
}
function integer(value: unknown, label: string, fallback: number, max: number) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
function identifiers(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])].sort();
}
export function parseIntegrityPortfolioRiskWeights(
  value: unknown,
): IntegrityPortfolioRiskWeights {
  if (value === undefined) return { ...DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS };
  const raw = object(value);
  const names = Object.keys(DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS);
  fields(raw, names);
  const result = { ...DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS };
  for (const name of names) {
    if (raw[name] !== undefined)
      (result as unknown as Record<string, number>)[name] =
        integer(raw[name], name, 0, 100);
  }
  return result;
}
export function parseIntegrityPortfolioRiskQuery(
  value: unknown,
): IntegrityPortfolioRiskQuery {
  const raw = object(value);
  fields(raw, [
    "minimumScore", "levels", "caseKeys", "workItemIds", "offset", "limit",
  ]);
  let levels: IntegrityPortfolioRiskLevel[] | undefined;
  if (raw.levels !== undefined) {
    if (!Array.isArray(raw.levels) || raw.levels.length > 4 ||
        raw.levels.some(x => !["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(x)))
      throw new WorkInputError("INVALID", "Invalid risk levels.");
    levels = [...new Set(raw.levels)] as IntegrityPortfolioRiskLevel[];
  }
  return {
    minimumScore: integer(raw.minimumScore, "minimum risk", 0, 100),
    ...(levels ? { levels } : {}),
    ...(raw.caseKeys === undefined ? {} :
      { caseKeys: identifiers(raw.caseKeys, "case keys") }),
    ...(raw.workItemIds === undefined ? {} :
      { workItemIds: identifiers(raw.workItemIds, "work IDs") }),
    offset: integer(raw.offset, "offset", 0, 1000000),
    limit: integer(raw.limit, "limit", 100, 1000),
  };
}
function riskLevel(score: number): IntegrityPortfolioRiskLevel {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}
function riskScore(factors: readonly IntegrityPortfolioRiskFactor[]) {
  return Math.min(100, factors.reduce((sum, factor) => sum + factor.points, 0));
}
function add(
  factors: IntegrityPortfolioRiskFactor[],
  condition: boolean,
  code: string,
  points: number,
  explanation: string,
) {
  if (condition && points > 0) factors.push({ code, points, explanation });
}
function findingsForCase(
  findings: readonly IntegrityEvidencePortfolioFinding[], caseKey: string,
) {
  return findings.filter(x => x.caseKey === caseKey);
}
function findingsForWork(
  findings: readonly IntegrityEvidencePortfolioFinding[], workItemId: string,
) {
  return findings.filter(x => x.workItemId === workItemId);
}
export function scoreIntegrityPortfolioCase(
  row: IntegrityEvidencePortfolioCase,
  findings: readonly IntegrityEvidencePortfolioFinding[],
  weights: IntegrityPortfolioRiskWeights = DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS,
): IntegrityPortfolioCaseRisk {
  const factors: IntegrityPortfolioRiskFactor[] = [];
  const related = findingsForCase(findings, row.caseKey);
  add(factors, !row.covered, "UNCOVERED_CASE", weights.uncoveredCase,
    "No coverage policy references this case.");
  add(factors, row.covered && !row.passing, "FAILING_CASE", weights.failingCase,
    "At least one coverage rule is not satisfied.");
  add(factors, row.activeWorkItemIds.length === 0, "NO_ACTIVE_WORK",
    weights.noActiveWork, "Case has no active remediation work association.");
  add(factors, row.withdrawnAssociations > 0 && row.activeAssociations === 0,
    "WITHDRAWN_ONLY", weights.withdrawnOnly,
    "All historical case associations are withdrawn.");
  add(factors, row.missingWorkItemIds.length > 0, "MISSING_REQUIRED_WORK",
    Math.min(100, row.missingWorkItemIds.length * weights.missingRequiredWork),
    "One or more required work items are missing.");
  const auditErrors = related.filter(x =>
    x.source === "AUDIT" && x.severity === "ERROR").length;
  const auditWarnings = related.filter(x =>
    x.source === "AUDIT" && x.severity === "WARNING").length;
  add(factors, auditErrors > 0, "AUDIT_ERRORS",
    Math.min(100, auditErrors * weights.auditError),
    "Audit integrity errors affect this case.");
  add(factors, auditWarnings > 0, "AUDIT_WARNINGS",
    Math.min(100, auditWarnings * weights.auditWarning),
    "Audit integrity warnings affect this case.");
  const score = riskScore(factors);
  return {
    caseKey: row.caseKey, score, level: riskLevel(score), factors,
    activeWorkItems: row.activeWorkItemIds.length,
    missingRequiredWorkItems: row.missingWorkItemIds.length,
    covered: row.covered, passing: row.passing,
  };
}
export function scoreIntegrityPortfolioWork(
  row: IntegrityEvidencePortfolioWork,
  findings: readonly IntegrityEvidencePortfolioFinding[],
  weights: IntegrityPortfolioRiskWeights = DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS,
): IntegrityPortfolioWorkRisk {
  const factors: IntegrityPortfolioRiskFactor[] = [];
  const related = findingsForWork(findings, row.workItemId);
  add(factors, row.singlePointOfFailure, "SINGLE_POINT_OF_FAILURE",
    weights.singlePointOfFailure,
    "This work item is the sole active work association for a dependent case.");
  add(factors, row.coverageDependencies === 0, "UNREFERENCED_WORK",
    weights.unreferencedWork,
    "No coverage policy explicitly requires this work item.");
  add(factors, row.activeCaseKeys.length === 0, "ORPHANED_WORK",
    weights.orphanedWork, "No active case is linked to this work item.");
  add(factors, row.requiredByCaseKeys.length > 1, "MULTIPLE_DEPENDENCIES",
    weights.multipleCaseDependencies,
    "Multiple cases rely on this work item for coverage.");
  const auditErrors = related.filter(x =>
    x.source === "AUDIT" && x.severity === "ERROR").length;
  add(factors, auditErrors > 0, "AUDIT_ERRORS",
    Math.min(100, auditErrors * weights.auditError),
    "Audit integrity errors affect this work item.");
  const score = riskScore(factors);
  return {
    workItemId: row.workItemId, score, level: riskLevel(score), factors,
    activeCases: row.activeCaseKeys.length,
    requiredByCases: row.requiredByCaseKeys.length,
    singlePointOfFailure: row.singlePointOfFailure,
  };
}
function descending<T extends { score: number }>(
  items: readonly T[], identity: (item: T) => string,
): T[] {
  return [...items].sort((a, b) =>
    b.score - a.score || identity(a).localeCompare(identity(b)));
}
function mean(values: readonly number[]) {
  return values.length === 0 ? 0 :
    values.reduce((sum, value) => sum + value, 0) / values.length;
}
export function analyzeIntegrityPortfolioRisk(
  portfolio: IntegrityEvidencePortfolio,
  weights: IntegrityPortfolioRiskWeights = DEFAULT_INTEGRITY_PORTFOLIO_RISK_WEIGHTS,
): IntegrityPortfolioRiskReport {
  const cases = descending(portfolio.cases.map(row =>
    scoreIntegrityPortfolioCase(row, portfolio.findings, weights)), x => x.caseKey);
  const workItems = descending(portfolio.workItems.map(row =>
    scoreIntegrityPortfolioWork(row, portfolio.findings, weights)), x => x.workItemId);
  const distribution: Record<IntegrityPortfolioRiskLevel, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
  };
  for (const item of [...cases, ...workItems]) distribution[item.level]++;
  return {
    schemaVersion: 1, captureId: portfolio.captureId,
    cases, workItems,
    highestRiskCases: cases.slice(0, 10).map(x => x.caseKey),
    highestRiskWorkItems: workItems.slice(0, 10).map(x => x.workItemId),
    distribution,
    meanCaseRisk: mean(cases.map(x => x.score)),
    meanWorkRisk: mean(workItems.map(x => x.score)),
    criticalFindings: portfolio.findings.filter(x =>
      x.severity === "ERROR").length,
    totalFindings: portfolio.findings.length,
  };
}
export function queryIntegrityPortfolioRisk(
  report: IntegrityPortfolioRiskReport,
  query: IntegrityPortfolioRiskQuery,
): IntegrityPortfolioRiskPage {
  const minimum = query.minimumScore ?? 0;
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(minimum) || minimum < 0 || minimum > 100 ||
      !Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid risk pagination.");
  const cases = report.cases.filter(x =>
    x.score >= minimum &&
    (!query.levels || query.levels.includes(x.level)) &&
    (!query.caseKeys || query.caseKeys.includes(x.caseKey)));
  const workItems = report.workItems.filter(x =>
    x.score >= minimum &&
    (!query.levels || query.levels.includes(x.level)) &&
    (!query.workItemIds || query.workItemIds.includes(x.workItemId)));
  return {
    captureId: report.captureId,
    totalCases: cases.length, totalWorkItems: workItems.length,
    offset, limit,
    cases: cases.slice(offset, offset + limit),
    workItems: workItems.slice(offset, offset + limit),
  };
}
export function compareIntegrityPortfolioRisk(
  before: IntegrityPortfolioRiskReport,
  after: IntegrityPortfolioRiskReport,
): IntegrityPortfolioRiskDelta {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Risk reports belong to different captures.");
  const previousCases = new Map(before.cases.map(x => [x.caseKey, x]));
  const currentCases = new Map(after.cases.map(x => [x.caseKey, x]));
  const previousWork = new Map(before.workItems.map(x => [x.workItemId, x]));
  const currentWork = new Map(after.workItems.map(x => [x.workItemId, x]));
  const improvedCases: string[] = [];
  const regressedCases: string[] = [];
  const improvedWorkItems: string[] = [];
  const regressedWorkItems: string[] = [];
  const newCriticalCases: string[] = [];
  const resolvedCriticalCases: string[] = [];
  const newCriticalWorkItems: string[] = [];
  const resolvedCriticalWorkItems: string[] = [];
  for (const [id, row] of currentCases) {
    const old = previousCases.get(id);
    if (!old) continue;
    if (row.score < old.score) improvedCases.push(id);
    if (row.score > old.score) regressedCases.push(id);
    if (row.level === "CRITICAL" && old.level !== "CRITICAL")
      newCriticalCases.push(id);
    if (row.level !== "CRITICAL" && old.level === "CRITICAL")
      resolvedCriticalCases.push(id);
  }
  for (const [id, row] of currentWork) {
    const old = previousWork.get(id);
    if (!old) continue;
    if (row.score < old.score) improvedWorkItems.push(id);
    if (row.score > old.score) regressedWorkItems.push(id);
    if (row.level === "CRITICAL" && old.level !== "CRITICAL")
      newCriticalWorkItems.push(id);
    if (row.level !== "CRITICAL" && old.level === "CRITICAL")
      resolvedCriticalWorkItems.push(id);
  }
  return {
    captureId: before.captureId,
    improvedCases: improvedCases.sort(), regressedCases: regressedCases.sort(),
    improvedWorkItems: improvedWorkItems.sort(),
    regressedWorkItems: regressedWorkItems.sort(),
    newCriticalCases: newCriticalCases.sort(),
    resolvedCriticalCases: resolvedCriticalCases.sort(),
    newCriticalWorkItems: newCriticalWorkItems.sort(),
    resolvedCriticalWorkItems: resolvedCriticalWorkItems.sort(),
    averageCaseScoreChange: after.meanCaseRisk - before.meanCaseRisk,
    averageWorkScoreChange: after.meanWorkRisk - before.meanWorkRisk,
  };
}
