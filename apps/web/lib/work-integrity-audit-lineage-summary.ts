import type { LineageReport, LineageNode } from "./work-integrity-audit-lineage";

/** Quantify the actual stored decisions traversed in a bounded source chain. */
export type LineageSummary = {
  organizationId: string;
  requestedEventId: string;
  decisions: { INVESTIGATE: number; ACKNOWLEDGE: number; DISMISS: number; REOPEN: number };
  uniqueActorReferences: number;
  missingActorReferences: number;
  distinctReviewedRevisions: number;
  earliestRecordedAt: string | null;
  latestRecordedAt: string | null;
  reviewRevisionMin: number | null;
  reviewRevisionMax: number | null;
  latestReviewRevisionMatchesWork: boolean | null;
  unresolvedSourceHistory: boolean;
  sequenceChronological: boolean;
  sequenceRevisionMonotonic: boolean;
  sourceCoverage: "ROOT_REACHED" | "PARTIAL";
  limitations: string[];
};
function checkSequence(nodes: readonly LineageNode[]) {
  let chronological = true;
  let revisions = true;
  const seen = new Set<string>();
  for (let i = 0; i < nodes.length; i++) {
    const current = nodes[i]!;
    if (seen.has(current.eventId))
      throw new Error("Duplicate event in bounded audit lineage summary.");
    seen.add(current.eventId);
    const next = nodes[i + 1];
    if (!next) continue;
    if (current.previousEventId !== next.eventId)
      throw new Error("Unexpected predecessor order in lineage summary.");
    if (current.occurredAt < next.occurredAt) chronological = false;
    if (current.reviewedRevision < next.reviewedRevision) revisions = false;
  }
  return { chronological, revisions };
}
export function summarizeAuditLineage(report: LineageReport): LineageSummary {
  if (!report.organizationId || !report.requestedEventId)
    throw new Error("Trusted audit lineage scope is required.");
  if (report.nodes[0]?.eventId !== report.requestedEventId)
    throw new Error("Lineage summary source does not begin at selected event.");
  if (report.nodes.some(node => node.workItemId !== report.workItemId))
    throw new Error("Cross-work audit event in source lineage summary.");
  const sequence = checkSequence(report.nodes);
  const decisions = { INVESTIGATE: 0, ACKNOWLEDGE: 0, DISMISS: 0, REOPEN: 0 };
  for (const node of report.nodes) {
    if (node.decision in decisions)
      decisions[node.decision as keyof typeof decisions]++;
  }
  const timestamps = report.nodes.map(node => node.occurredAt).sort();
  const revisions = report.nodes.map(node => node.reviewedRevision);
  const uniqueActorReferences = new Set(report.nodes.map(node =>
    node.actorUserId).filter((id): id is string => id !== null)).size;
  return {
    organizationId: report.organizationId,
    requestedEventId: report.requestedEventId,
    decisions,
    uniqueActorReferences,
    missingActorReferences: report.nodes.filter(node =>
      node.actorUserId === null).length,
    distinctReviewedRevisions: new Set(revisions).size,
    earliestRecordedAt: timestamps[0] ?? null,
    latestRecordedAt: timestamps[timestamps.length - 1] ?? null,
    reviewRevisionMin: revisions.length ? Math.min(...revisions) : null,
    reviewRevisionMax: revisions.length ? Math.max(...revisions) : null,
    latestReviewRevisionMatchesWork: report.latestReviewIsCurrent,
    unresolvedSourceHistory: !report.sourceChainComplete,
    sequenceChronological: sequence.chronological,
    sequenceRevisionMonotonic: sequence.revisions,
    sourceCoverage: report.sourceChainComplete ? "ROOT_REACHED" : "PARTIAL",
    limitations: [
      "Counts describe the selected predecessor walk, not all reviews for the work item.",
      "A missing actor may reflect account lifecycle rather than missing audit records.",
      "Reaching the recorded root is not independent evidence of event immutability.",
      "Decision history cannot certify remediation, compliance or security-control effectiveness.",
    ],
  };
}
