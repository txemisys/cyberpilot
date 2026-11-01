import type { LedgerEntry, LedgerPage } from "./work-integrity-audit-ledger";

/**
 * Identify audit-ledger inspection candidates within the selected raw page.
 * Findings are evidence-conscious: an event outside this bounded page is
 * unknown, and no review is treated as a security-control verification.
 */
export type LedgerInsightKind =
  | "HISTORICAL_WORK_REVISION"
  | "WORK_ITEM_UNAVAILABLE"
  | "REVIEW_ACTOR_UNAVAILABLE"
  | "REVIEW_PREDECESSOR_OUTSIDE_PAGE"
  | "REVIEW_TIME_REVERSED"
  | "DUPLICATE_CASE_EVENT_TIME"
  | "MULTIPLE_DECISIONS_SAME_REVISION"
  | "REVIEW_DECISION_REOPENED"
  | "REVIEW_RATIONALE_MISSING"
  | "REVIEW_CHAIN_CROSSES_CASE"
  | "REVIEW_REVISION_DECREASED";
export type LedgerInsight = {
  kind: LedgerInsightKind;
  severity: "ERROR" | "REVIEW" | "UNKNOWN" | "INFO";
  eventId: string;
  workItemId: string;
  caseKey: string;
  occurredAt: string;
  explanation: string;
  followup: string;
  relatedEventId: string | null;
};
export type LedgerInsights = {
  organizationId: string;
  generatedAt: string;
  scanned: number;
  caseIdentities: number;
  workIdentities: number;
  explicitPredecessorLinks: number;
  linksAvailableOnPage: number;
  predecessorsOutsidePage: number;
  currentWorkRevisionMatches: number;
  outdatedWorkRevisions: number;
  missingCurrentWork: number;
  sourceCoverage: "PAGE_ONLY" | "PAGE_WITH_OUTSIDE_PREDECESSORS";
  counts: Record<LedgerInsight["severity"], number>;
  byKind: Partial<Record<LedgerInsightKind, number>>;
  alerts: LedgerInsight[];
  limitations: string[];
};
function key(entry: LedgerEntry): string {
  return JSON.stringify([entry.workItemId, entry.code, entry.resourceId]);
}
export function inspectLedgerInsights(page: LedgerPage): LedgerInsights {
  const entries = [...page.entries].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) || a.eventId.localeCompare(b.eventId));
  const byId = new Map(entries.map(item => [item.eventId, item]));
  const byCase = new Map<string, LedgerEntry[]>();
  for (const entry of entries) {
    if (entry.organizationId !== page.organizationId)
      throw new Error("Foreign event in tenant-scoped ledger insights.");
    const identity = key(entry);
    const current = byCase.get(identity) ?? [];
    current.push(entry);
    byCase.set(identity, current);
  }
  const alerts: LedgerInsight[] = [];
  const counts: LedgerInsights["counts"] = { ERROR: 0, REVIEW: 0, UNKNOWN: 0, INFO: 0 };
  const byKind: LedgerInsights["byKind"] = {};
  const add = (
    entry: LedgerEntry,
    kind: LedgerInsightKind, severity: LedgerInsight["severity"],
    explanation: string, followup: string,
    relatedEventId: string | null = null,
  ) => {
    counts[severity]++;
    byKind[kind] = (byKind[kind] ?? 0) + 1;
    alerts.push({
      kind, severity, eventId: entry.eventId,
      workItemId: entry.workItemId, caseKey: key(entry),
      occurredAt: entry.occurredAt,
      explanation, followup, relatedEventId,
    });
  };
  for (const entry of entries) {
    if (entry.reviewedRevisionIsCurrent === false) add(
      entry, "HISTORICAL_WORK_REVISION", "INFO",
      "The audit decision records a different work-item revision than is currently stored.",
      "Inspect the work revision history before relying on this historical decision.",
    );
    if (entry.currentWorkRevision === null) add(
      entry, "WORK_ITEM_UNAVAILABLE", "UNKNOWN",
      "The reviewed work item is unavailable in the current bounded lookup.",
      "Check whether the work item was archived or removed and consult source history.",
    );
    if (entry.actorUserId === null) add(
      entry, "REVIEW_ACTOR_UNAVAILABLE", "REVIEW",
      "The recorded review has no current linked user actor.",
      "Check the original audit actor and account lifecycle.",
    );
    if (entry.predecessorEventId !== null && !entry.predecessorInPage) add(
      entry, "REVIEW_PREDECESSOR_OUTSIDE_PAGE", "UNKNOWN",
      "The linked predecessor is not included in the selected raw event page.",
      "Inspect earlier pages or open the complete bounded work-item audit chain.",
      entry.predecessorEventId,
    );
    if (entry.predecessorChronologicallyPrior === false) add(
      entry, "REVIEW_TIME_REVERSED", "REVIEW",
      "A linked review predecessor has a later timestamp.",
      "Compare source event order and recorded clocks.",
      entry.predecessorEventId,
    );
    if (!entry.rationale.trim()) add(
      entry, "REVIEW_RATIONALE_MISSING", "REVIEW",
      "No explanatory rationale was available in the decoded audit record.",
      "Record a new auditable explanation rather than rewriting history.",
    );
    if (entry.decision === "REOPEN") add(
      entry, "REVIEW_DECISION_REOPENED", "INFO",
      "An earlier review disposition was reopened.",
      "Confirm a follow-up investigation has a current owner and linked evidence.",
      entry.predecessorEventId,
    );
    const predecessor = entry.predecessorEventId ?
      byId.get(entry.predecessorEventId) : undefined;
    if (predecessor && key(predecessor) !== key(entry)) add(
      entry, "REVIEW_CHAIN_CROSSES_CASE", "ERROR",
      "The predecessor event belongs to another diagnostic case.",
      "Investigate inconsistent event links in the authoritative tenant audit history.",
      predecessor.eventId,
    );
    if (predecessor && predecessor.revision > entry.revision) add(
      entry, "REVIEW_REVISION_DECREASED", "REVIEW",
      "The reviewed work revision decreased along the event chain.",
      "Reconcile the work and audit event revision sequence.",
      predecessor.eventId,
    );
  }
  for (const group of byCase.values()) {
    for (let i = 1; i < group.length; i++) {
      const before = group[i - 1]!;
      const after = group[i]!;
      if (before.occurredAt === after.occurredAt) add(
        after, "DUPLICATE_CASE_EVENT_TIME", "REVIEW",
        "Two different recorded decisions for one diagnostic share a timestamp.",
        "Inspect event identity, server ordering and transaction history.",
        before.eventId,
      );
      if (before.revision === after.revision &&
          before.decision !== after.decision &&
          after.predecessorEventId !== before.eventId) add(
        after, "MULTIPLE_DECISIONS_SAME_REVISION", "REVIEW",
        "A different decision on the same work revision does not directly link its predecessor.",
        "Reconstruct the complete event sequence and check for concurrent decisions.",
        before.eventId,
      );
    }
  }
  const rank = { ERROR: 0, REVIEW: 1, UNKNOWN: 2, INFO: 3 };
  alerts.sort((a, b) =>
    rank[a.severity] - rank[b.severity] ||
    b.occurredAt.localeCompare(a.occurredAt) ||
    a.eventId.localeCompare(b.eventId) || a.kind.localeCompare(b.kind));
  return {
    organizationId: page.organizationId,
    generatedAt: page.generatedAt,
    scanned: entries.length,
    caseIdentities: byCase.size,
    workIdentities: new Set(entries.map(item => item.workItemId)).size,
    explicitPredecessorLinks: entries.filter(item =>
      item.predecessorEventId !== null).length,
    linksAvailableOnPage: entries.filter(item =>
      item.predecessorEventId !== null && item.predecessorInPage).length,
    predecessorsOutsidePage: entries.filter(item =>
      item.predecessorEventId !== null && !item.predecessorInPage).length,
    currentWorkRevisionMatches: entries.filter(item =>
      item.reviewedRevisionIsCurrent === true).length,
    outdatedWorkRevisions: entries.filter(item =>
      item.reviewedRevisionIsCurrent === false).length,
    missingCurrentWork: entries.filter(item =>
      item.currentWorkRevision === null).length,
    sourceCoverage: entries.some(item =>
      item.predecessorEventId !== null && !item.predecessorInPage)
      ? "PAGE_WITH_OUTSIDE_PREDECESSORS" : "PAGE_ONLY",
    counts, byKind, alerts,
    limitations: [
      "Insights describe only matching decoded events on the selected bounded raw page.",
      "Event continuity cannot be proven when predecessor events are outside the page.",
      "Repeated decisions may be valid human actions; anomalies require investigation, not automatic deletion.",
      "This analysis performs no work-state changes and cannot certify security-control effectiveness.",
    ],
  };
}
export function ledgerInsightsCsv(result: LedgerInsights): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const columns = [
    "occurredAt", "eventId", "workItemId", "caseKey", "kind",
    "severity", "relatedEventId", "explanation", "followup",
  ];
  const lines = [columns.map(quote).join(",")];
  for (const issue of result.alerts) {
    lines.push([
      issue.occurredAt, issue.eventId, issue.workItemId, issue.caseKey,
      issue.kind, issue.severity, issue.relatedEventId,
      issue.explanation, issue.followup,
    ].map(quote).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
