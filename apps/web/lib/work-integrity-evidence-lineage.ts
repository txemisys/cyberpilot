import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import { reviewIntegrityLinks } from "./work-integrity-link-review";
import {
  buildIntegrityEvidenceGraph, connectedIntegrityEvidenceComponents,
  type IntegrityEvidenceGraph, type IntegrityEvidenceGraphNode,
} from "./work-integrity-evidence-graph";

export type IntegrityLineagePath = {
  from: string;
  to: string;
  nodes: string[];
  auditIds: string[];
  hops: number;
};
export type IntegrityLineageNeighborhood = {
  origin: string;
  depth: number;
  nodes: IntegrityEvidenceGraphNode[];
  auditIds: string[];
  distances: Record<string, number>;
};
export type IntegrityLineageImpact = {
  auditId: string;
  source: string;
  target: string;
  disconnectedByRemoval: boolean;
  beforeComponents: number;
  afterComponents: number;
  affectedCaseKeys: string[];
  affectedWorkItemIds: string[];
};
export type IntegrityLineageOverview = {
  captureId: string;
  nodeCount: number;
  edgeCount: number;
  activeEdgeCount: number;
  connectedComponentCount: number;
  bridges: IntegrityLineageImpact[];
  highestDegreeNodes: IntegrityEvidenceGraphNode[];
};
function adjacency(graph: IntegrityEvidenceGraph, activeOnly: boolean) {
  const result = new Map<string, { to: string; auditId: string }[]>();
  for (const node of graph.nodes) result.set(node.id, []);
  for (const edge of graph.edges) {
    if (activeOnly && edge.state !== "ACTIVE") continue;
    result.get(edge.source)?.push({ to: edge.target, auditId: edge.auditId });
    result.get(edge.target)?.push({ to: edge.source, auditId: edge.auditId });
  }
  for (const edges of result.values())
    edges.sort((a, b) => a.to.localeCompare(b.to) || a.auditId.localeCompare(b.auditId));
  return result;
}
function ensureNode(graph: IntegrityEvidenceGraph, id: string) {
  if (!graph.nodes.some(node => node.id === id))
    throw new WorkInputError("MISSING", "Lineage graph node not found.");
}
export function shortestIntegrityLineagePath(
  graph: IntegrityEvidenceGraph,
  from: string, to: string, activeOnly = true,
): IntegrityLineagePath | null {
  ensureNode(graph, from);
  ensureNode(graph, to);
  const neighbors = adjacency(graph, activeOnly);
  const previous = new Map<string, { node: string; auditId: string }>();
  const visited = new Set([from]);
  const queue = [from];
  for (let i = 0; i < queue.length; i++) {
    const current = queue[i]!;
    if (current === to) break;
    for (const edge of neighbors.get(current) ?? []) {
      if (visited.has(edge.to)) continue;
      visited.add(edge.to);
      previous.set(edge.to, { node: current, auditId: edge.auditId });
      queue.push(edge.to);
    }
  }
  if (!visited.has(to)) return null;
  const nodes = [to];
  const auditIds: string[] = [];
  let cursor = to;
  while (cursor !== from) {
    const step = previous.get(cursor);
    if (!step) throw new WorkInputError("CONFLICT", "Lineage traversal incomplete.");
    auditIds.push(step.auditId);
    cursor = step.node;
    nodes.push(cursor);
  }
  return {
    from, to, nodes: nodes.reverse(), auditIds: auditIds.reverse(),
    hops: auditIds.length,
  };
}
export function integrityLineageNeighborhood(
  graph: IntegrityEvidenceGraph, origin: string,
  depth = 2, activeOnly = true,
): IntegrityLineageNeighborhood {
  ensureNode(graph, origin);
  if (!Number.isSafeInteger(depth) || depth < 0 || depth > 20)
    throw new WorkInputError("INVALID", "Invalid lineage neighborhood depth.");
  const neighbors = adjacency(graph, activeOnly);
  const distances = new Map([[origin, 0]]);
  const queue = [origin];
  const edges = new Set<string>();
  for (let i = 0; i < queue.length; i++) {
    const current = queue[i]!;
    const distance = distances.get(current)!;
    if (distance >= depth) continue;
    for (const edge of neighbors.get(current) ?? []) {
      edges.add(edge.auditId);
      if (!distances.has(edge.to)) {
        distances.set(edge.to, distance + 1);
        queue.push(edge.to);
      }
    }
  }
  return {
    origin, depth,
    nodes: graph.nodes.filter(node => distances.has(node.id)),
    auditIds: [...edges].sort(),
    distances: Object.fromEntries([...distances].sort(([a], [b]) => a.localeCompare(b))),
  };
}
function graphWithoutEdge(graph: IntegrityEvidenceGraph, auditId: string) {
  const edges = graph.edges.filter(edge => edge.auditId !== auditId);
  return {
    ...graph, edges,
    activeEdges: edges.filter(edge => edge.state === "ACTIVE").length,
    withdrawnEdges: edges.filter(edge => edge.state === "WITHDRAWN").length,
  };
}
export function evaluateIntegrityLineageImpact(
  graph: IntegrityEvidenceGraph, auditId: string,
): IntegrityLineageImpact {
  const edge = graph.edges.find(x => x.auditId === auditId);
  if (!edge) throw new WorkInputError("MISSING", "Association audit event not found.");
  const before = connectedIntegrityEvidenceComponents(graph);
  const after = connectedIntegrityEvidenceComponents(graphWithoutEdge(graph, auditId));
  const relevant = after.filter(component =>
    component.cases.some(x => edge.source === "case:" + x) ||
    component.workItems.some(x => edge.target === "work:" + x));
  return {
    auditId, source: edge.source, target: edge.target,
    disconnectedByRemoval: after.length > before.length,
    beforeComponents: before.length, afterComponents: after.length,
    affectedCaseKeys: [...new Set(relevant.flatMap(x => x.cases))].sort(),
    affectedWorkItemIds: [...new Set(relevant.flatMap(x => x.workItems))].sort(),
  };
}
export function analyzeIntegrityLineage(
  graph: IntegrityEvidenceGraph,
): IntegrityLineageOverview {
  const activeEdges = graph.edges.filter(edge => edge.state === "ACTIVE");
  const bridges = activeEdges.map(edge =>
    evaluateIntegrityLineageImpact(graph, edge.auditId))
    .filter(impact => impact.disconnectedByRemoval);
  return {
    captureId: graph.captureId,
    nodeCount: graph.nodes.length, edgeCount: graph.edges.length,
    activeEdgeCount: graph.activeEdges,
    connectedComponentCount: connectedIntegrityEvidenceComponents(graph).length,
    bridges: bridges.sort((a, b) => a.auditId.localeCompare(b.auditId)),
    highestDegreeNodes: [...graph.nodes].sort((a, b) =>
      b.activeDegree - a.activeDegree || a.id.localeCompare(b.id)).slice(0, 20),
  };
}
export function inspectIntegrityLineage(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  options?: { from?: string; to?: string; origin?: string; depth?: number },
) {
  const report = reviewIntegrityLinks(captureId, events);
  const graph = buildIntegrityEvidenceGraph(captureId, report.associations);
  const overview = analyzeIntegrityLineage(graph);
  const path = options?.from && options?.to
    ? shortestIntegrityLineagePath(graph, options.from, options.to) : null;
  const neighborhood = options?.origin
    ? integrityLineageNeighborhood(graph, options.origin, options.depth) : null;
  return { overview, path, neighborhood, findings: report.findings };
}
