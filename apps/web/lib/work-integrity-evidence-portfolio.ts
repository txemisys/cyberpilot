import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, type LinkReviewAssociation,
  type LinkReviewFinding, type LinkReviewReport,
} from "./work-integrity-link-review";
import {
  buildIntegrityEvidenceGraph, connectedIntegrityEvidenceComponents,
  type IntegrityEvidenceGraph,
} from "./work-integrity-evidence-graph";
import {
  evaluateIntegrityEvidenceCoverage,
  type IntegrityEvidenceCoveragePolicy,
  type IntegrityEvidenceCoverageReport,
} from "./work-integrity-evidence-coverage";

export type IntegrityEvidencePortfolioInput = {
  captureId: string;
  policies: IntegrityEvidenceCoveragePolicy[];
  includeHistorical?: boolean;
  includeUncovered?: boolean;
  asOf?: string;
};
export type IntegrityEvidencePortfolioCase = {
  caseKey: string;
  activeWorkItemIds: string[];
  withdrawnWorkItemIds: string[];
  policyIds: string[];
  requiredWorkItemIds: string[];
  missingWorkItemIds: string[];
  associationCount: number;
  activeAssociations: number;
  withdrawnAssociations: number;
  firstLinkedAt: string | null;
  lastActivityAt: string | null;
  actorUserIds: string[];
  findings: string[];
  covered: boolean;
  passing: boolean;
};
export type IntegrityEvidencePortfolioWork = {
  workItemId: string;
  activeCaseKeys: string[];
  withdrawnCaseKeys: string[];
  requiredByCaseKeys: string[];
  linkedByActorIds: string[];
  activeAssociations: number;
  withdrawnAssociations: number;
  coverageDependencies: number;
  singlePointOfFailure: boolean;
};
export type IntegrityEvidencePortfolioPolicy = {
  policyIndex: number;
  passed: boolean;
  passingRules: number;
  failingRules: number;
  findings: number;
  affectedCases: string[];
  affectedWorkItems: string[];
};
export type IntegrityEvidencePortfolioFinding = {
  source: "AUDIT" | "COVERAGE" | "TOPOLOGY";
  code: string;
  severity: "ERROR" | "WARNING";
  caseKey: string | null;
  workItemId: string | null;
  auditId: string | null;
  policyIndex: number | null;
  explanation: string;
};
export type IntegrityEvidencePortfolio = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string | null;
  cases: IntegrityEvidencePortfolioCase[];
  workItems: IntegrityEvidencePortfolioWork[];
  policies: IntegrityEvidencePortfolioPolicy[];
  findings: IntegrityEvidencePortfolioFinding[];
  totals: {
    cases: number;
    workItems: number;
    activeAssociations: number;
    withdrawnAssociations: number;
    policyPasses: number;
    policyFailures: number;
    uncoveredCases: number;
    uncoveredWorkItems: number;
    errors: number;
    warnings: number;
    disconnectedComponents: number;
  };
};
export type IntegrityEvidencePortfolioQuery = {
  caseKeys?: string[];
  workItemIds?: string[];
  policyIndexes?: number[];
  states?: ("PASSING" | "FAILING" | "UNCOVERED")[];
  includeFindings?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityEvidencePortfolioPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  cases: IntegrityEvidencePortfolioCase[];
  workItems: IntegrityEvidencePortfolioWork[];
  findings: IntegrityEvidencePortfolioFinding[];
};
export type IntegrityEvidencePortfolioChange = {
  captureId: string;
  beforeEvaluatedAt: string | null;
  afterEvaluatedAt: string | null;
  newlyActiveCases: string[];
  noLongerActiveCases: string[];
  newlyUncoveredCases: string[];
  newlyCoveredCases: string[];
  regressedCases: string[];
  improvedCases: string[];
  addedWorkItems: string[];
  removedWorkItems: string[];
  introducedFindings: IntegrityEvidencePortfolioFinding[];
  resolvedFindings: IntegrityEvidencePortfolioFinding[];
};
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const unique = (values: readonly string[]) => [...new Set(values)].sort(compare);
const validTimestamp = (value: unknown): value is string =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
function ensureObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected a portfolio request object.");
  return value as Record<string, unknown>;
}
function ensureFields(raw: Record<string, unknown>, fields: readonly string[]) {
  if (Object.keys(raw).some(x => !fields.includes(x)))
    throw new WorkInputError("INVALID", "Unknown portfolio field.");
}
function ensureId(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || value.length > 1500 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function ensureArray(value: unknown, label: string, max: number) {
  if (!Array.isArray(value) || value.length > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function optionalIds(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  return unique(ensureArray(value, label, 1000).map(x => ensureId(x, label)));
}
function optionalInteger(value: unknown, label: string, fallback: number, max: number) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
export function parseIntegrityEvidencePortfolioInput(
  value: unknown,
): IntegrityEvidencePortfolioInput {
  const raw = ensureObject(value);
  ensureFields(raw, [
    "captureId", "policies", "includeHistorical", "includeUncovered", "asOf",
  ]);
  const captureId = ensureId(raw.captureId, "capture ID");
  if (!/^[a-zA-Z0-9_-]{5,100}$/.test(captureId))
    throw new WorkInputError("INVALID", "Invalid capture ID.");
  if (raw.includeHistorical !== undefined && typeof raw.includeHistorical !== "boolean")
    throw new WorkInputError("INVALID", "Invalid historical flag.");
  if (raw.includeUncovered !== undefined && typeof raw.includeUncovered !== "boolean")
    throw new WorkInputError("INVALID", "Invalid uncovered flag.");
  if (raw.asOf !== undefined && !validTimestamp(raw.asOf))
    throw new WorkInputError("INVALID", "Invalid portfolio timestamp.");
  const policies = ensureArray(raw.policies, "coverage policies", 100) as
    IntegrityEvidenceCoveragePolicy[];
  if (policies.some(x => !x || x.captureId !== captureId))
    throw new WorkInputError("INVALID", "Cross-capture portfolio policy.");
  return {
    captureId, policies,
    includeHistorical: raw.includeHistorical !== false,
    includeUncovered: raw.includeUncovered !== false,
    ...(raw.asOf ? { asOf: raw.asOf as string } : {}),
  };
}
export function parseIntegrityEvidencePortfolioQuery(
  value: unknown,
): IntegrityEvidencePortfolioQuery {
  const raw = ensureObject(value);
  ensureFields(raw, [
    "caseKeys", "workItemIds", "policyIndexes", "states",
    "includeFindings", "offset", "limit",
  ]);
  const caseKeys = optionalIds(raw.caseKeys, "case keys");
  const workItemIds = optionalIds(raw.workItemIds, "work item IDs");
  let policyIndexes: number[] | undefined;
  if (raw.policyIndexes !== undefined) {
    const indexes = ensureArray(raw.policyIndexes, "policy indexes", 100);
    if (indexes.some(x => !Number.isSafeInteger(x) || x < 0 || x > 100))
      throw new WorkInputError("INVALID", "Invalid policy index.");
    policyIndexes = [...new Set(indexes as number[])].sort((a, b) => a - b);
  }
  let states: ("PASSING" | "FAILING" | "UNCOVERED")[] | undefined;
  if (raw.states !== undefined) {
    const values = ensureArray(raw.states, "portfolio states", 3);
    if (values.some(x => !["PASSING", "FAILING", "UNCOVERED"].includes(x)))
      throw new WorkInputError("INVALID", "Invalid portfolio state.");
    states = [...new Set(values)] as ("PASSING" | "FAILING" | "UNCOVERED")[];
  }
  if (raw.includeFindings !== undefined && typeof raw.includeFindings !== "boolean")
    throw new WorkInputError("INVALID", "Invalid findings flag.");
  return {
    ...(caseKeys ? { caseKeys } : {}),
    ...(workItemIds ? { workItemIds } : {}),
    ...(policyIndexes ? { policyIndexes } : {}),
    ...(states ? { states } : {}),
    includeFindings: raw.includeFindings === true,
    offset: optionalInteger(raw.offset, "offset", 0, 1000000),
    limit: optionalInteger(raw.limit, "limit", 100, 1000),
  };
}
function associationTime(item: LinkReviewAssociation) {
  return item.withdrawnAt ?? item.createdAt;
}
function latest(current: string | null, value: string) {
  return current === null || current < value ? value : current;
}
function earliest(current: string | null, value: string) {
  return current === null || current > value ? value : current;
}
function auditFinding(item: LinkReviewFinding): IntegrityEvidencePortfolioFinding {
  return {
    source: "AUDIT", code: item.code, severity: item.severity,
    caseKey: item.caseKey, workItemId: item.workItemId,
    auditId: item.auditId, policyIndex: null,
    explanation: item.explanation,
  };
}
function coverageFindings(
  report: IntegrityEvidenceCoverageReport, index: number,
): IntegrityEvidencePortfolioFinding[] {
  return report.findings.map(x => ({
    source: "COVERAGE" as const, code: x.code,
    severity: "WARNING" as const,
    caseKey: x.caseKey, workItemId: x.workItemId,
    auditId: null, policyIndex: index, explanation: x.explanation,
  }));
}
function graphFindings(graph: IntegrityEvidenceGraph): IntegrityEvidencePortfolioFinding[] {
  const components = connectedIntegrityEvidenceComponents({
    ...graph, edges: graph.edges.filter(x => x.state === "ACTIVE"),
  });
  const findings: IntegrityEvidencePortfolioFinding[] = [];
  for (const node of graph.nodes) {
    if (node.activeDegree === 0 && node.withdrawnDegree > 0) {
      findings.push({
        source: "TOPOLOGY", code: "WITHDRAWN_ONLY_NODE",
        severity: "WARNING",
        caseKey: node.kind === "CASE" ? node.label : null,
        workItemId: node.kind === "WORK" ? node.label : null,
        auditId: null, policyIndex: null,
        explanation: "Historical associations exist but none remain active.",
      });
    }
  }
  if (components.length > 1) {
    findings.push({
      source: "TOPOLOGY", code: "DISCONNECTED_EVIDENCE_GRAPH",
      severity: "WARNING", caseKey: null, workItemId: null,
      auditId: null, policyIndex: null,
      explanation: "Active evidence associations form disconnected components.",
    });
  }
  return findings;
}
function emptyCase(caseKey: string): IntegrityEvidencePortfolioCase {
  return {
    caseKey, activeWorkItemIds: [], withdrawnWorkItemIds: [],
    policyIds: [], requiredWorkItemIds: [], missingWorkItemIds: [],
    associationCount: 0, activeAssociations: 0, withdrawnAssociations: 0,
    firstLinkedAt: null, lastActivityAt: null,
    actorUserIds: [], findings: [], covered: false, passing: false,
  };
}
function emptyWork(workItemId: string): IntegrityEvidencePortfolioWork {
  return {
    workItemId, activeCaseKeys: [], withdrawnCaseKeys: [],
    requiredByCaseKeys: [], linkedByActorIds: [],
    activeAssociations: 0, withdrawnAssociations: 0,
    coverageDependencies: 0, singlePointOfFailure: false,
  };
}
function indexAssociations(associations: readonly LinkReviewAssociation[]) {
  const cases = new Map<string, IntegrityEvidencePortfolioCase>();
  const work = new Map<string, IntegrityEvidencePortfolioWork>();
  for (const association of associations) {
    const c = cases.get(association.caseKey) ?? emptyCase(association.caseKey);
    const w = work.get(association.workItemId) ?? emptyWork(association.workItemId);
    c.associationCount++;
    c.firstLinkedAt = earliest(c.firstLinkedAt, association.createdAt);
    c.lastActivityAt = latest(c.lastActivityAt, associationTime(association));
    if (association.createdBy) {
      c.actorUserIds.push(association.createdBy);
      w.linkedByActorIds.push(association.createdBy);
    }
    if (association.withdrawnBy) {
      c.actorUserIds.push(association.withdrawnBy);
      w.linkedByActorIds.push(association.withdrawnBy);
    }
    if (association.state === "ACTIVE") {
      c.activeAssociations++; w.activeAssociations++;
      c.activeWorkItemIds.push(association.workItemId);
      w.activeCaseKeys.push(association.caseKey);
    } else {
      c.withdrawnAssociations++; w.withdrawnAssociations++;
      c.withdrawnWorkItemIds.push(association.workItemId);
      w.withdrawnCaseKeys.push(association.caseKey);
    }
    cases.set(c.caseKey, c);
    work.set(w.workItemId, w);
  }
  return { cases, work };
}
function indexPolicies(
  policies: readonly IntegrityEvidenceCoveragePolicy[],
  graph: IntegrityEvidenceGraph,
  associations: readonly LinkReviewAssociation[],
  cases: Map<string, IntegrityEvidencePortfolioCase>,
  work: Map<string, IntegrityEvidencePortfolioWork>,
) {
  const reports: IntegrityEvidencePortfolioPolicy[] = [];
  const findings: IntegrityEvidencePortfolioFinding[] = [];
  for (const [index, policy] of policies.entries()) {
    const evaluation = evaluateIntegrityEvidenceCoverage(graph, associations, policy);
    const affectedCases = new Set<string>();
    const affectedWorkItems = new Set<string>();
    for (const rule of policy.rules) {
      const row = cases.get(rule.caseKey) ?? emptyCase(rule.caseKey);
      row.covered = true;
      row.policyIds.push(rule.id);
      row.requiredWorkItemIds.push(...rule.requiredWorkItemIds ?? []);
      affectedCases.add(rule.caseKey);
      for (const workId of rule.requiredWorkItemIds ?? []) {
        affectedWorkItems.add(workId);
        const workRow = work.get(workId) ?? emptyWork(workId);
        workRow.requiredByCaseKeys.push(rule.caseKey);
        work.set(workId, workRow);
      }
      cases.set(rule.caseKey, row);
    }
    for (const row of evaluation.cases) {
      const target = cases.get(row.caseKey)!;
      target.missingWorkItemIds.push(...row.missingWorkItemIds);
      target.passing = target.policyIds.length === 1
        ? row.passed : target.passing && row.passed;
    }
    const policyFindings = coverageFindings(evaluation, index);
    for (const item of policyFindings) {
      if (item.caseKey) cases.get(item.caseKey)?.findings.push(item.code);
      findings.push(item);
    }
    reports.push({
      policyIndex: index, passed: evaluation.passed,
      passingRules: evaluation.passingRules,
      failingRules: evaluation.failingRules,
      findings: evaluation.findings.length,
      affectedCases: [...affectedCases].sort(compare),
      affectedWorkItems: [...affectedWorkItems].sort(compare),
    });
  }
  return { reports, findings };
}
function finalizeCases(
  cases: Map<string, IntegrityEvidencePortfolioCase>,
  includeUncovered: boolean,
) {
  return [...cases.values()].filter(x => includeUncovered || x.covered).map(x => ({
    ...x,
    activeWorkItemIds: unique(x.activeWorkItemIds),
    withdrawnWorkItemIds: unique(x.withdrawnWorkItemIds),
    policyIds: unique(x.policyIds),
    requiredWorkItemIds: unique(x.requiredWorkItemIds),
    missingWorkItemIds: unique(x.missingWorkItemIds),
    actorUserIds: unique(x.actorUserIds),
    findings: unique(x.findings),
  })).sort((a, b) => compare(a.caseKey, b.caseKey));
}
function finalizeWork(
  work: Map<string, IntegrityEvidencePortfolioWork>,
  cases: readonly IntegrityEvidencePortfolioCase[],
  includeUncovered: boolean,
) {
  const coveredCases = new Set(cases.filter(x => x.covered).map(x => x.caseKey));
  return [...work.values()].filter(x =>
    includeUncovered || x.requiredByCaseKeys.some(key => coveredCases.has(key)))
    .map(x => {
      const dependencies = unique(x.requiredByCaseKeys);
      return {
        ...x,
        activeCaseKeys: unique(x.activeCaseKeys),
        withdrawnCaseKeys: unique(x.withdrawnCaseKeys),
        requiredByCaseKeys: dependencies,
        linkedByActorIds: unique(x.linkedByActorIds),
        coverageDependencies: dependencies.length,
        singlePointOfFailure: dependencies.length > 0 &&
          dependencies.some(key => {
            const row = cases.find(c => c.caseKey === key);
            return row?.activeWorkItemIds.length === 1 &&
              row.activeWorkItemIds[0] === x.workItemId;
          }),
      };
    }).sort((a, b) => compare(a.workItemId, b.workItemId));
}
export function buildIntegrityEvidencePortfolio(
  input: IntegrityEvidencePortfolioInput,
  events: readonly IntegrityLinkHistoryEvent[],
): IntegrityEvidencePortfolio {
  const visible = input.asOf
    ? events.filter(x => x.occurredAt <= input.asOf!) : events;
  const report: LinkReviewReport = reviewIntegrityLinks(input.captureId, visible);
  const associations = input.includeHistorical === false
    ? report.associations.filter(x => x.state === "ACTIVE") : report.associations;
  const graph = buildIntegrityEvidenceGraph(input.captureId, associations);
  const indexed = indexAssociations(associations);
  const indexedPolicies = indexPolicies(
    input.policies, graph, report.associations, indexed.cases, indexed.work);
  const cases = finalizeCases(indexed.cases, input.includeUncovered !== false);
  const workItems = finalizeWork(
    indexed.work, cases, input.includeUncovered !== false);
  const findings = [
    ...report.findings.map(auditFinding),
    ...indexedPolicies.findings,
    ...graphFindings(graph),
  ].sort((a, b) =>
    compare(a.source, b.source) || compare(a.code, b.code) ||
    compare(a.caseKey ?? "", b.caseKey ?? "") ||
    compare(a.workItemId ?? "", b.workItemId ?? ""));
  for (const item of findings) {
    if (item.caseKey && item.source !== "COVERAGE")
      indexed.cases.get(item.caseKey)?.findings.push(item.code);
  }
  const active = report.associations.filter(x => x.state === "ACTIVE");
  const withdrawn = report.associations.filter(x => x.state === "WITHDRAWN");
  const activeGraph = {
    ...graph, edges: graph.edges.filter(x => x.state === "ACTIVE"),
  };
  return {
    schemaVersion: 1, captureId: input.captureId,
    evaluatedAt: input.asOf ?? null,
    cases, workItems, policies: indexedPolicies.reports, findings,
    totals: {
      cases: cases.length, workItems: workItems.length,
      activeAssociations: active.length,
      withdrawnAssociations: withdrawn.length,
      policyPasses: indexedPolicies.reports.filter(x => x.passed).length,
      policyFailures: indexedPolicies.reports.filter(x => !x.passed).length,
      uncoveredCases: cases.filter(x => !x.covered).length,
      uncoveredWorkItems: workItems.filter(x => x.coverageDependencies === 0).length,
      errors: findings.filter(x => x.severity === "ERROR").length,
      warnings: findings.filter(x => x.severity === "WARNING").length,
      disconnectedComponents: connectedIntegrityEvidenceComponents(activeGraph).length,
    },
  };
}
export function queryIntegrityEvidencePortfolio(
  portfolio: IntegrityEvidencePortfolio,
  query: IntegrityEvidencePortfolioQuery,
): IntegrityEvidencePortfolioPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid portfolio pagination.");
  const selected = portfolio.cases.filter(row =>
    (query.caseKeys === undefined || query.caseKeys.includes(row.caseKey)) &&
    (query.workItemIds === undefined || query.workItemIds.some(id =>
      row.activeWorkItemIds.includes(id) ||
      row.withdrawnWorkItemIds.includes(id))) &&
    (query.policyIndexes === undefined || query.policyIndexes.some(index =>
      portfolio.policies[index]?.affectedCases.includes(row.caseKey))) &&
    (query.states === undefined || query.states.includes(
      !row.covered ? "UNCOVERED" : row.passing ? "PASSING" : "FAILING")));
  const cases = selected.slice(offset, offset + limit);
  const ids = new Set(cases.map(x => x.caseKey));
  const workIds = new Set(cases.flatMap(x => [
    ...x.activeWorkItemIds, ...x.withdrawnWorkItemIds,
    ...x.requiredWorkItemIds,
  ]));
  return {
    captureId: portfolio.captureId, total: selected.length, offset, limit,
    hasMore: offset + limit < selected.length, cases,
    workItems: portfolio.workItems.filter(x => workIds.has(x.workItemId)),
    findings: query.includeFindings ? portfolio.findings.filter(x =>
      (x.caseKey !== null && ids.has(x.caseKey)) ||
      (x.caseKey === null && x.workItemId !== null &&
        workIds.has(x.workItemId))) : [],
  };
}
function findingKey(item: IntegrityEvidencePortfolioFinding) {
  return JSON.stringify([
    item.source, item.code, item.caseKey, item.workItemId,
    item.auditId, item.policyIndex,
  ]);
}
export function compareIntegrityEvidencePortfolios(
  before: IntegrityEvidencePortfolio,
  after: IntegrityEvidencePortfolio,
): IntegrityEvidencePortfolioChange {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Cannot compare different captures.");
  const old = new Map(before.cases.map(x => [x.caseKey, x]));
  const current = new Map(after.cases.map(x => [x.caseKey, x]));
  const newlyActiveCases: string[] = [];
  const noLongerActiveCases: string[] = [];
  const newlyUncoveredCases: string[] = [];
  const newlyCoveredCases: string[] = [];
  const regressedCases: string[] = [];
  const improvedCases: string[] = [];
  for (const key of unique([...old.keys(), ...current.keys()])) {
    const previous = old.get(key);
    const next = current.get(key);
    if (!previous?.activeAssociations && next?.activeAssociations)
      newlyActiveCases.push(key);
    if (previous?.activeAssociations && !next?.activeAssociations)
      noLongerActiveCases.push(key);
    if (previous?.covered && next && !next.covered)
      newlyUncoveredCases.push(key);
    if (!previous?.covered && next?.covered)
      newlyCoveredCases.push(key);
    if (previous?.passing && next && !next.passing)
      regressedCases.push(key);
    if (previous && !previous.passing && next?.passing)
      improvedCases.push(key);
  }
  const oldWork = new Set(before.workItems.map(x => x.workItemId));
  const newWork = new Set(after.workItems.map(x => x.workItemId));
  const oldFindings = new Map(before.findings.map(x => [findingKey(x), x]));
  const newFindings = new Map(after.findings.map(x => [findingKey(x), x]));
  return {
    captureId: before.captureId,
    beforeEvaluatedAt: before.evaluatedAt,
    afterEvaluatedAt: after.evaluatedAt,
    newlyActiveCases, noLongerActiveCases,
    newlyUncoveredCases, newlyCoveredCases,
    regressedCases, improvedCases,
    addedWorkItems: [...newWork].filter(x => !oldWork.has(x)).sort(compare),
    removedWorkItems: [...oldWork].filter(x => !newWork.has(x)).sort(compare),
    introducedFindings: [...newFindings].filter(([key]) =>
      !oldFindings.has(key)).map(([, x]) => x),
    resolvedFindings: [...oldFindings].filter(([key]) =>
      !newFindings.has(key)).map(([, x]) => x),
  };
}
export function buildIntegrityPortfolioAtCheckpoints(
  input: IntegrityEvidencePortfolioInput,
  events: readonly IntegrityLinkHistoryEvent[],
  checkpoints: readonly string[],
) {
  if (!Array.isArray(checkpoints) || checkpoints.length < 1 ||
      checkpoints.length > 100 || checkpoints.some(x => !validTimestamp(x)))
    throw new WorkInputError("INVALID", "Invalid portfolio checkpoints.");
  const sorted = unique(checkpoints);
  if (sorted.length !== checkpoints.length)
    throw new WorkInputError("INVALID", "Duplicate portfolio checkpoint.");
  const snapshots = sorted.map(asOf =>
    buildIntegrityEvidencePortfolio({ ...input, asOf }, events));
  const changes = snapshots.slice(1).map((after, index) =>
    compareIntegrityEvidencePortfolios(snapshots[index]!, after));
  return {
    captureId: input.captureId, checkpoints: sorted,
    snapshots, changes,
    regressions: changes.reduce((n, x) => n + x.regressedCases.length, 0),
    improvements: changes.reduce((n, x) => n + x.improvedCases.length, 0),
    lastPassing: snapshots.at(-1)!.totals.policyFailures === 0,
  };
}
