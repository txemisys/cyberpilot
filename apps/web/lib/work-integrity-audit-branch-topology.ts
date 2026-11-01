import type { BranchReport, BranchNode } from "./work-integrity-audit-branch-explorer";

/** Derive auditable operational graph topology from source event links. */
export type BranchTopology = {
  organizationId: string; workItemId: string;
  nodesInspected: number; linkedEdges: number;
  rootNodes: number; terminalNodes: number;
  forkNodes: number; unresolvedPredecessors: number;
  isolatedNodes: number; maximumObservedDepth: number | null;
  currentRevisionReviews: number;
  historicalRevisionReviews: number;
  missingActorReferences: number;
  latestEventPerCase: { caseKey: string; eventId: string; decision: string }[];
  coverage: "COMPLETE_SOURCE_WINDOW" | "TRUNCATED_OR_MALFORMED";
  limitations: string[];
};
function isValidNode(node: BranchNode, report: BranchReport): void {
  if (node.revision < 1 || !Number.isSafeInteger(node.revision))
    throw new Error("Invalid source review revision in branch topology.");
  if (!report.nodes.some(item => item.id === node.id))
    throw new Error("Unrecognized source event in branch topology.");
}
export function summarizeBranchTopology(report: BranchReport): BranchTopology {
  const ids = new Map(report.nodes.map(node => [node.id, node]));
  if (ids.size !== report.nodes.length)
    throw new Error("Duplicate source event identity in branch topology.");
  const latest = new Map<string, BranchNode>();
  let linkedEdges = 0;
  let unresolvedPredecessors = 0;
  let isolatedNodes = 0;
  for (const node of report.nodes) {
    isValidNode(node, report);
    if (node.previousEventId) {
      if (ids.has(node.previousEventId)) linkedEdges++;
      else unresolvedPredecessors++;
    }
    if (!node.previousEventId && !node.successorIds.length)
      isolatedNodes++;
    const prior = latest.get(node.caseKey);
    if (!prior || node.occurredAt > prior.occurredAt ||
        (node.occurredAt === prior.occurredAt && node.id > prior.id))
      latest.set(node.caseKey, node);
    for (const childId of node.successorIds) {
      const child = ids.get(childId);
      if (!child || child.previousEventId !== node.id)
        throw new Error("Source successor linkage inconsistent with predecessor reference.");
    }
  }
  const depths = report.nodes.map(node => node.depthFromRoot)
    .filter((depth): depth is number => depth !== null);
  return {
    organizationId: report.organizationId, workItemId: report.workItemId,
    nodesInspected: report.nodes.length,
    linkedEdges, rootNodes: report.nodes.filter(node => node.isRoot).length,
    terminalNodes: report.nodes.filter(node => node.isTerminal).length,
    forkNodes: report.nodes.filter(node => node.successorIds.length > 1).length,
    unresolvedPredecessors, isolatedNodes,
    maximumObservedDepth: depths.length ? Math.max(...depths) : null,
    currentRevisionReviews: report.nodes.filter(node =>
      node.revision === report.workRevision).length,
    historicalRevisionReviews: report.nodes.filter(node =>
      node.revision !== report.workRevision).length,
    missingActorReferences: report.nodes.filter(node => node.actorUserId === null).length,
    latestEventPerCase: [...latest].map(([caseKey, node]) => ({
      caseKey, eventId: node.id, decision: node.decision,
    })).sort((a, b) => a.caseKey.localeCompare(b.caseKey)),
    coverage: report.sourceTruncated || report.malformedRows > 0
      ? "TRUNCATED_OR_MALFORMED" : "COMPLETE_SOURCE_WINDOW",
    limitations: [
      "Only stored review events within this tenant-scoped source query are represented.",
      "A complete query window does not independently authenticate audit immutability.",
      "Current work revision comparison is contextual and cannot verify remediation.",
      "Isolated recorded review roots may be valid first decisions, not automatic failures.",
    ],
  };
}
