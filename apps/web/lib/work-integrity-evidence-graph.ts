import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, type LinkReviewReport,
  type LinkReviewAssociation, type LinkReviewFinding,
} from "./work-integrity-link-review";

export type IntegrityEvidenceQuery = {
  captureId: string;
  caseKeys?: string[];
  workItemIds?: string[];
  actors?: string[];
  states?: ("ACTIVE" | "WITHDRAWN")[];
  includeFindings?: boolean;
  includeEvents?: boolean;
  after?: string;
  before?: string;
  offset?: number;
  limit?: number;
};
export type IntegrityEvidenceCaseSummary = {
  caseKey: string;
  associationCount: number;
  activeCount: number;
  withdrawnCount: number;
  workItemIds: string[];
  firstLinkedAt: string | null;
  lastChangedAt: string | null;
  actors: string[];
  findingCount: number;
};
export type IntegrityEvidenceWorkSummary = {
  workItemId: string;
  associationCount: number;
  activeCount: number;
  withdrawnCount: number;
  caseKeys: string[];
  firstLinkedAt: string | null;
  lastChangedAt: string | null;
  actors: string[];
  findingCount: number;
};
export type IntegrityEvidenceGraphNode = {
  id: string;
  kind: "CASE" | "WORK";
  label: string;
  degree: number;
  activeDegree: number;
  withdrawnDegree: number;
};
export type IntegrityEvidenceGraphEdge = {
  auditId: string;
  source: string;
  target: string;
  state: "ACTIVE" | "WITHDRAWN";
  createdAt: string;
  withdrawnAt: string | null;
};
export type IntegrityEvidenceGraph = {
  captureId: string;
  nodes: IntegrityEvidenceGraphNode[];
  edges: IntegrityEvidenceGraphEdge[];
  isolatedNodes: number;
  activeEdges: number;
  withdrawnEdges: number;
};
export type IntegrityEvidenceQueryResult = {
  schemaVersion: 1;
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  associations: LinkReviewAssociation[];
  findings: LinkReviewFinding[];
  events: IntegrityLinkHistoryEvent[];
  cases: IntegrityEvidenceCaseSummary[];
  workItems: IntegrityEvidenceWorkSummary[];
};
export type IntegrityEvidenceGraphStats = {
  totalCases: number;
  totalWorkItems: number;
  totalEdges: number;
  activeEdges: number;
  withdrawnEdges: number;
  connectedComponents: number;
  largestComponent: number;
  casesWithoutActiveWork: string[];
  workWithoutActiveCases: string[];
};
export type IntegrityEvidenceComponent = {
  id: string;
  cases: string[];
  workItems: string[];
  edges: number;
  activeEdges: number;
  withdrawnEdges: number;
};
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
function isTimestamp(value: string) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function stringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function numberField(value: unknown, label: string, fallback: number, max: number) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < 0 ||
      (value as number) > max)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as number;
}
export function parseIntegrityEvidenceQuery(value: unknown): IntegrityEvidenceQuery {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Evidence query must be an object.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => ![
    "captureId", "caseKeys", "workItemIds", "actors", "states",
    "includeFindings", "includeEvents", "after", "before", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown evidence query field.");
  if (typeof raw.captureId !== "string" ||
      !/^[a-zA-Z0-9_-]{5,100}$/.test(raw.captureId))
    throw new WorkInputError("INVALID", "Invalid capture ID.");
  const caseKeys = stringArray(raw.caseKeys, "case keys");
  const workItemIds = stringArray(raw.workItemIds, "work item IDs");
  const actors = stringArray(raw.actors, "actors");
  const states = stringArray(raw.states, "states");
  if (states?.some(x => x !== "ACTIVE" && x !== "WITHDRAWN"))
    throw new WorkInputError("INVALID", "Invalid evidence state.");
  if (raw.includeFindings !== undefined && typeof raw.includeFindings !== "boolean")
    throw new WorkInputError("INVALID", "Invalid findings flag.");
  if (raw.includeEvents !== undefined && typeof raw.includeEvents !== "boolean")
    throw new WorkInputError("INVALID", "Invalid events flag.");
  for (const key of ["after", "before"]) {
    if (raw[key] !== undefined &&
        (typeof raw[key] !== "string" || !isTimestamp(raw[key] as string)))
      throw new WorkInputError("INVALID", "Invalid " + key + " timestamp.");
  }
  if (raw.after && raw.before && raw.after > raw.before)
    throw new WorkInputError("INVALID", "After must precede before.");
  const limit = numberField(raw.limit, "limit", 100, 1000);
  if (limit < 1) throw new WorkInputError("INVALID", "Limit must be positive.");
  return {
    captureId: raw.captureId,
    ...(caseKeys ? { caseKeys } : {}),
    ...(workItemIds ? { workItemIds } : {}),
    ...(actors ? { actors } : {}),
    ...(states ? { states: states as ("ACTIVE" | "WITHDRAWN")[] } : {}),
    ...(raw.includeFindings === undefined ? {} : { includeFindings: raw.includeFindings as boolean }),
    ...(raw.includeEvents === undefined ? {} : { includeEvents: raw.includeEvents as boolean }),
    ...(raw.after === undefined ? {} : { after: raw.after as string }),
    ...(raw.before === undefined ? {} : { before: raw.before as string }),
    offset: numberField(raw.offset, "offset", 0, 1000000),
    limit,
  };
}
function unique(values: readonly (string | null)[]) {
  return [...new Set(values.filter((x): x is string => x !== null))].sort(compare);
}
function earliest(a: string | null, b: string): string {
  return a === null || b < a ? b : a;
}
function latest(a: string | null, b: string): string {
  return a === null || b > a ? b : a;
}
export function summarizeIntegrityEvidenceCases(
  associations: readonly LinkReviewAssociation[],
  findings: readonly LinkReviewFinding[] = [],
): IntegrityEvidenceCaseSummary[] {
  const result = new Map<string, IntegrityEvidenceCaseSummary>();
  for (const association of associations) {
    const current = result.get(association.caseKey) ?? {
      caseKey: association.caseKey, associationCount: 0,
      activeCount: 0, withdrawnCount: 0, workItemIds: [],
      firstLinkedAt: null, lastChangedAt: null, actors: [], findingCount: 0,
    };
    current.associationCount++;
    if (association.state === "ACTIVE") current.activeCount++;
    else current.withdrawnCount++;
    current.workItemIds.push(association.workItemId);
    current.firstLinkedAt = earliest(current.firstLinkedAt, association.createdAt);
    current.lastChangedAt = latest(current.lastChangedAt,
      association.withdrawnAt ?? association.createdAt);
    current.actors.push(...unique([association.createdBy, association.withdrawnBy]));
    result.set(association.caseKey, current);
  }
  for (const finding of findings) {
    const row = result.get(finding.caseKey);
    if (row) row.findingCount++;
  }
  return [...result.values()].map(row => ({
    ...row, workItemIds: unique(row.workItemIds), actors: unique(row.actors),
  })).sort((a, b) => compare(a.caseKey, b.caseKey));
}
export function summarizeIntegrityEvidenceWork(
  associations: readonly LinkReviewAssociation[],
  findings: readonly LinkReviewFinding[] = [],
): IntegrityEvidenceWorkSummary[] {
  const result = new Map<string, IntegrityEvidenceWorkSummary>();
  for (const association of associations) {
    const current = result.get(association.workItemId) ?? {
      workItemId: association.workItemId, associationCount: 0,
      activeCount: 0, withdrawnCount: 0, caseKeys: [],
      firstLinkedAt: null, lastChangedAt: null, actors: [], findingCount: 0,
    };
    current.associationCount++;
    if (association.state === "ACTIVE") current.activeCount++;
    else current.withdrawnCount++;
    current.caseKeys.push(association.caseKey);
    current.firstLinkedAt = earliest(current.firstLinkedAt, association.createdAt);
    current.lastChangedAt = latest(current.lastChangedAt,
      association.withdrawnAt ?? association.createdAt);
    current.actors.push(...unique([association.createdBy, association.withdrawnBy]));
    result.set(association.workItemId, current);
  }
  for (const finding of findings) {
    const row = result.get(finding.workItemId);
    if (row) row.findingCount++;
  }
  return [...result.values()].map(row => ({
    ...row, caseKeys: unique(row.caseKeys), actors: unique(row.actors),
  })).sort((a, b) => compare(a.workItemId, b.workItemId));
}
function included(
  association: LinkReviewAssociation, query: IntegrityEvidenceQuery,
): boolean {
  return (query.caseKeys === undefined || query.caseKeys.includes(association.caseKey)) &&
    (query.workItemIds === undefined || query.workItemIds.includes(association.workItemId)) &&
    (query.states === undefined || query.states.includes(association.state)) &&
    (query.actors === undefined ||
      (association.createdBy !== null && query.actors.includes(association.createdBy)) ||
      (association.withdrawnBy !== null && query.actors.includes(association.withdrawnBy))) &&
    (query.after === undefined || association.createdAt >= query.after) &&
    (query.before === undefined || association.createdAt <= query.before);
}
export function queryIntegrityEvidence(
  report: LinkReviewReport,
  events: readonly IntegrityLinkHistoryEvent[],
  query: IntegrityEvidenceQuery,
): IntegrityEvidenceQueryResult {
  if (query.captureId !== report.captureId)
    throw new WorkInputError("INVALID", "Evidence query capture mismatch.");
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new WorkInputError("INVALID", "Invalid evidence pagination.");
  const selected = report.associations.filter(x => included(x, query));
  const page = selected.slice(offset, offset + limit);
  const auditIds = new Set(page.map(x => x.auditId));
  const withdrawalIds = new Set(page.map(x => x.withdrawalAuditId)
    .filter((x): x is string => x !== null));
  const findings = query.includeFindings ? report.findings.filter(x =>
    auditIds.has(x.auditId) || withdrawalIds.has(x.auditId) ||
    (x.relatedAuditId !== null && auditIds.has(x.relatedAuditId))) : [];
  const visibleEvents = query.includeEvents ? events.filter(x =>
    auditIds.has(x.auditId) || withdrawalIds.has(x.auditId)) : [];
  return {
    schemaVersion: 1, captureId: report.captureId,
    total: selected.length, offset, limit,
    hasMore: offset + limit < selected.length,
    associations: page, findings, events: visibleEvents,
    cases: summarizeIntegrityEvidenceCases(page, findings),
    workItems: summarizeIntegrityEvidenceWork(page, findings),
  };
}
export function buildIntegrityEvidenceGraph(
  captureId: string,
  associations: readonly LinkReviewAssociation[],
): IntegrityEvidenceGraph {
  const cases = new Map<string, IntegrityEvidenceGraphNode>();
  const works = new Map<string, IntegrityEvidenceGraphNode>();
  const edges: IntegrityEvidenceGraphEdge[] = [];
  for (const item of associations) {
    if (item.captureId !== captureId)
      throw new WorkInputError("INVALID", "Cross-capture graph association.");
    const source = "case:" + item.caseKey;
    const target = "work:" + item.workItemId;
    const c = cases.get(source) ?? {
      id: source, kind: "CASE" as const, label: item.caseKey,
      degree: 0, activeDegree: 0, withdrawnDegree: 0,
    };
    const w = works.get(target) ?? {
      id: target, kind: "WORK" as const, label: item.workItemId,
      degree: 0, activeDegree: 0, withdrawnDegree: 0,
    };
    c.degree++; w.degree++;
    if (item.state === "ACTIVE") { c.activeDegree++; w.activeDegree++; }
    else { c.withdrawnDegree++; w.withdrawnDegree++; }
    cases.set(source, c); works.set(target, w);
    edges.push({
      auditId: item.auditId, source, target, state: item.state,
      createdAt: item.createdAt, withdrawnAt: item.withdrawnAt,
    });
  }
  return {
    captureId,
    nodes: [...cases.values(), ...works.values()].sort((a, b) => compare(a.id, b.id)),
    edges: edges.sort((a, b) => compare(a.auditId, b.auditId)),
    isolatedNodes: 0,
    activeEdges: edges.filter(x => x.state === "ACTIVE").length,
    withdrawnEdges: edges.filter(x => x.state === "WITHDRAWN").length,
  };
}
export function connectedIntegrityEvidenceComponents(
  graph: IntegrityEvidenceGraph,
): IntegrityEvidenceComponent[] {
  const adjacency = new Map<string, Set<string>>();
  for (const node of graph.nodes) adjacency.set(node.id, new Set());
  for (const edge of graph.edges) {
    adjacency.get(edge.source)?.add(edge.target);
    adjacency.get(edge.target)?.add(edge.source);
  }
  const visited = new Set<string>();
  const components: IntegrityEvidenceComponent[] = [];
  for (const node of graph.nodes) {
    if (visited.has(node.id)) continue;
    const queue = [node.id];
    visited.add(node.id);
    const ids: string[] = [];
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i]!;
      ids.push(id);
      for (const neighbor of adjacency.get(id) ?? []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
    const members = new Set(ids);
    const edges = graph.edges.filter(edge =>
      members.has(edge.source) && members.has(edge.target));
    components.push({
      id: ids.sort(compare)[0]!,
      cases: ids.filter(x => x.startsWith("case:")).map(x => x.slice(5)).sort(compare),
      workItems: ids.filter(x => x.startsWith("work:")).map(x => x.slice(5)).sort(compare),
      edges: edges.length,
      activeEdges: edges.filter(x => x.state === "ACTIVE").length,
      withdrawnEdges: edges.filter(x => x.state === "WITHDRAWN").length,
    });
  }
  return components.sort((a, b) => compare(a.id, b.id));
}
export function summarizeIntegrityEvidenceGraph(
  graph: IntegrityEvidenceGraph,
): IntegrityEvidenceGraphStats {
  const components = connectedIntegrityEvidenceComponents(graph);
  return {
    totalCases: graph.nodes.filter(x => x.kind === "CASE").length,
    totalWorkItems: graph.nodes.filter(x => x.kind === "WORK").length,
    totalEdges: graph.edges.length,
    activeEdges: graph.activeEdges, withdrawnEdges: graph.withdrawnEdges,
    connectedComponents: components.length,
    largestComponent: components.reduce((max, item) =>
      Math.max(max, item.cases.length + item.workItems.length), 0),
    casesWithoutActiveWork: graph.nodes.filter(x =>
      x.kind === "CASE" && x.activeDegree === 0).map(x => x.label).sort(compare),
    workWithoutActiveCases: graph.nodes.filter(x =>
      x.kind === "WORK" && x.activeDegree === 0).map(x => x.label).sort(compare),
  };
}
export function inspectIntegrityEvidenceGraph(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
) {
  const report = reviewIntegrityLinks(captureId, events);
  const graph = buildIntegrityEvidenceGraph(captureId, report.associations);
  return {
    graph, stats: summarizeIntegrityEvidenceGraph(graph),
    components: connectedIntegrityEvidenceComponents(graph),
    findings: report.findings,
  };
}
