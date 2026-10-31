import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot, SnapshotComparison, CaseDelta } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { caseDimensions, groupCases } from "./work-integrity-analytics";

/**
 * Deterministic analyst worklists from recorded case diagnostics.
 * Worklists are suggestions only: they never mutate cases or attest controls.
 */
export type ReviewPriority = "P0" | "P1" | "P2" | "P3" | "P4";
export type ReviewReason =
  | "CRITICAL_UNREVIEWED" | "CRITICAL_REOPENED" | "STALE_REVIEW"
  | "INCOMPLETE_COVERAGE" | "ATTENTION_UNREVIEWED" | "INVESTIGATION_OPEN"
  | "REOPENED" | "UNREVIEWED" | "REVIEWED" | "HISTORICAL";
export type ReviewWorklistEntry = {
  caseKey: string;
  workItemId: string;
  code: string;
  resourceId: string;
  priority: ReviewPriority;
  reasons: ReviewReason[];
  severity: CaseRow["severity"];
  state: CaseRow["state"];
  currentRevision: number;
  reviewedRevision: number | null;
  reviewEventId: string | null;
  completeCoverage: boolean;
  historicalOnly: boolean;
  suggestedAction: string;
  caveat: string;
};
export type ReviewWorklist = {
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  total: number;
  entries: ReviewWorklistEntry[];
  byPriority: Record<ReviewPriority, number>;
  byReason: Record<ReviewReason, number>;
  limitations: string[];
};
export type WorklistFilter = {
  priorities?: ReviewPriority[];
  reasons?: ReviewReason[];
  workItemIds?: string[];
  codes?: string[];
  includeReviewed?: boolean;
  limit?: number;
  offset?: number;
};
export type WorklistPage = {
  totalMatching: number;
  offset: number;
  limit: number;
  nextOffset: number | null;
  entries: ReviewWorklistEntry[];
};
export type ReviewBatch = {
  batchId: string;
  priority: ReviewPriority;
  entries: ReviewWorklistEntry[];
  distinctWorkItems: number;
  diagnosticCodes: string[];
  completeCoverage: boolean;
  requiresReassessment: boolean;
};
const priorities: ReviewPriority[] = ["P0", "P1", "P2", "P3", "P4"];
const reasons: ReviewReason[] = [
  "CRITICAL_UNREVIEWED", "CRITICAL_REOPENED", "STALE_REVIEW",
  "INCOMPLETE_COVERAGE", "ATTENTION_UNREVIEWED", "INVESTIGATION_OPEN",
  "REOPENED", "UNREVIEWED", "REVIEWED", "HISTORICAL",
];
const rank = (priority: ReviewPriority): number => priorities.indexOf(priority);
function priorityOf(row: CaseRow): ReviewPriority {
  if (row.state === "STALE") return "P0";
  if (row.severity === "critical" && row.state === "UNREVIEWED") return "P0";
  if (row.severity === "critical" && row.state === "REOPENED") return "P0";
  if (!row.completeCoverage) return "P1";
  if (row.state === "UNREVIEWED" && row.severity === "attention") return "P1";
  if (row.state === "INVESTIGATING" || row.state === "REOPENED") return "P2";
  if (row.state === "UNREVIEWED") return "P2";
  if (row.historicalOnly) return "P3";
  return "P4";
}
function reasonsOf(row: CaseRow): ReviewReason[] {
  const result: ReviewReason[] = [];
  if (row.state === "STALE") result.push("STALE_REVIEW");
  if (row.severity === "critical" && row.state === "UNREVIEWED")
    result.push("CRITICAL_UNREVIEWED");
  if (row.severity === "critical" && row.state === "REOPENED")
    result.push("CRITICAL_REOPENED");
  if (!row.completeCoverage) result.push("INCOMPLETE_COVERAGE");
  if (row.severity === "attention" && row.state === "UNREVIEWED")
    result.push("ATTENTION_UNREVIEWED");
  if (row.state === "INVESTIGATING") result.push("INVESTIGATION_OPEN");
  if (row.state === "REOPENED") result.push("REOPENED");
  if (row.state === "UNREVIEWED") result.push("UNREVIEWED");
  if (row.reviewEventId) result.push("REVIEWED");
  if (row.historicalOnly) result.push("HISTORICAL");
  return result;
}
function actionFor(row: CaseRow): string {
  if (!row.completeCoverage)
    return "Retrieve complete linked history before deciding whether the diagnostic remains present.";
  if (row.state === "STALE")
    return "Reassess the recorded review against the current work item revision.";
  if (row.state === "UNREVIEWED")
    return "Assign an authorized reviewer to investigate the recorded anomaly.";
  if (row.state === "REOPENED")
    return "Continue the reopened investigation and document the next review.";
  if (row.state === "INVESTIGATING")
    return "Continue investigation and record a reasoned review decision.";
  if (row.historicalOnly)
    return "Inspect historical evidence before deciding whether the prior review is still relevant.";
  return "Retain the review record; independently verify any claimed remediation.";
}
export function worklistEntry(row: CaseRow): ReviewWorklistEntry {
  return {
    caseKey: row.key, workItemId: row.workItemId,
    code: row.code, resourceId: row.resourceId,
    priority: priorityOf(row), reasons: reasonsOf(row),
    severity: row.severity, state: row.state,
    currentRevision: row.taskRevision, reviewedRevision: row.reviewedRevision,
    reviewEventId: row.reviewEventId,
    completeCoverage: row.completeCoverage, historicalOnly: row.historicalOnly,
    suggestedAction: actionFor(row),
    caveat: "Human triage does not verify control effectiveness or close a security finding.",
  };
}
export function buildReviewWorklist(snapshot: CaseSnapshot): ReviewWorklist {
  const entries = snapshot.cases.map(worklistEntry)
    .sort((a, b) => rank(a.priority) - rank(b.priority) ||
      a.workItemId.localeCompare(b.workItemId) ||
      a.code.localeCompare(b.code) || a.resourceId.localeCompare(b.resourceId));
  const byPriority = Object.fromEntries(priorities.map(p => [p, 0])) as Record<ReviewPriority, number>;
  const byReason = Object.fromEntries(reasons.map(r => [r, 0])) as Record<ReviewReason, number>;
  for (const entry of entries) {
    byPriority[entry.priority]++;
    for (const reason of entry.reasons) byReason[reason]++;
  }
  return {
    organizationId: snapshot.organizationId, capturedAt: snapshot.capturedAt,
    complete: snapshot.complete, total: entries.length,
    entries, byPriority, byReason,
    limitations: [
      "Priority is a deterministic operational triage heuristic, not an incident severity score.",
      ...(!snapshot.complete ? ["Partial snapshot may omit other cases requiring review."] : []),
    ],
  };
}
export function filterReviewWorklist(
  worklist: ReviewWorklist, options: WorklistFilter = {},
): WorklistPage {
  const limit = options.limit ?? 25;
  const offset = options.offset ?? 0;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000 ||
      !Number.isSafeInteger(offset) || offset < 0)
    throw new Error("Invalid worklist pagination.");
  const prioritiesSet = options.priorities ? new Set(options.priorities) : null;
  const reasonsSet = options.reasons ? new Set(options.reasons) : null;
  const ids = options.workItemIds ? new Set(options.workItemIds) : null;
  const codes = options.codes ? new Set(options.codes) : null;
  const filtered = worklist.entries.filter(entry => {
    if (prioritiesSet && !prioritiesSet.has(entry.priority)) return false;
    if (reasonsSet && !entry.reasons.some(reason => reasonsSet.has(reason))) return false;
    if (ids && !ids.has(entry.workItemId)) return false;
    if (codes && !codes.has(entry.code)) return false;
    if (options.includeReviewed === false && entry.reviewEventId) return false;
    return true;
  });
  return {
    totalMatching: filtered.length, offset, limit,
    nextOffset: offset + limit < filtered.length ? offset + limit : null,
    entries: filtered.slice(offset, offset + limit),
  };
}
export function groupReviewBatches(
  worklist: ReviewWorklist, batchSize = 25,
): ReviewBatch[] {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000)
    throw new Error("Invalid review batch size.");
  const batches: ReviewBatch[] = [];
  for (const priority of priorities) {
    const entries = worklist.entries.filter(entry => entry.priority === priority);
    for (let offset = 0; offset < entries.length; offset += batchSize) {
      const items = entries.slice(offset, offset + batchSize);
      batches.push({
        batchId: `${worklist.capturedAt}:${priority}:${Math.floor(offset / batchSize) + 1}`,
        priority, entries: items,
        distinctWorkItems: new Set(items.map(x => x.workItemId)).size,
        diagnosticCodes: [...new Set(items.map(x => x.code))].sort(),
        completeCoverage: items.every(x => x.completeCoverage) && worklist.complete,
        requiresReassessment: items.some(x => x.reasons.includes("STALE_REVIEW")),
      });
    }
  }
  return batches;
}
export type ReviewChange = {
  key: string;
  beforePriority: ReviewPriority | null;
  afterPriority: ReviewPriority | null;
  beforeState: CaseRow["state"] | null;
  afterState: CaseRow["state"] | null;
  kind: string;
  escalated: boolean;
  deescalated: boolean;
  indeterminate: boolean;
};
export type ReviewWorklistDiff = {
  organizationId: string;
  complete: boolean;
  escalations: number;
  deescalations: number;
  indeterminate: number;
  changes: ReviewChange[];
  caveat: string;
};
export function compareReviewWorklists(
  before: CaseSnapshot, after: CaseSnapshot,
): ReviewWorklistDiff {
  const comparison = compareCaseSnapshots(before, after);
  const changes = comparison.deltas.filter(delta => delta.kind !== "UNCHANGED").map(delta => {
    const beforePriority = delta.before ? priorityOf(delta.before) : null;
    const afterPriority = delta.after ? priorityOf(delta.after) : null;
    const indeterminate = delta.kind === "INDETERMINATE";
    return {
      key: delta.key, beforePriority, afterPriority,
      beforeState: delta.before?.state ?? null,
      afterState: delta.after?.state ?? null,
      kind: delta.kind,
      escalated: !indeterminate && beforePriority !== null && afterPriority !== null &&
        rank(afterPriority) < rank(beforePriority),
      deescalated: !indeterminate && beforePriority !== null && afterPriority !== null &&
        rank(afterPriority) > rank(beforePriority),
      indeterminate,
    };
  });
  return {
    organizationId: comparison.organizationId, complete: comparison.complete,
    escalations: changes.filter(x => x.escalated).length,
    deescalations: changes.filter(x => x.deescalated).length,
    indeterminate: changes.filter(x => x.indeterminate).length,
    changes,
    caveat: "A reduced triage priority does not establish that a security issue was resolved.",
  };
}
export type WorklistOverview = {
  totalCases: number;
  distinctWorkItems: number;
  criticalCases: number;
  unreviewedCases: number;
  staleReviews: number;
  priorityDistribution: ReviewWorklist["byPriority"];
  topDiagnosticCodes: Array<{ code: string; count: number }>;
  suggestedBatches: number;
};
export function reviewWorklistOverview(
  snapshot: CaseSnapshot, batchSize = 25,
): WorklistOverview {
  const list = buildReviewWorklist(snapshot);
  const dimensions = caseDimensions(snapshot.cases);
  return {
    totalCases: list.total,
    distinctWorkItems: Object.keys(dimensions.byWorkItem).length,
    criticalCases: dimensions.bySeverity.critical,
    unreviewedCases: dimensions.unreviewed,
    staleReviews: dimensions.stale,
    priorityDistribution: list.byPriority,
    topDiagnosticCodes: groupCases(snapshot.cases, "code")
      .slice(0, 10).map(group => ({ code: group.key, count: group.count })),
    suggestedBatches: groupReviewBatches(list, batchSize).length,
  };
}
export function reviewWorklistCsv(worklist: ReviewWorklist): string {
  const escape = (value: unknown) => {
    const text = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(text) ? "'" + text : text;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const columns = [
    "priority", "workItemId", "code", "resourceId", "state",
    "severity", "currentRevision", "reviewedRevision", "completeCoverage",
    "reasons", "suggestedAction",
  ] as const;
  const lines = [columns.map(escape).join(",")];
  for (const entry of worklist.entries) {
    lines.push([
      entry.priority, entry.workItemId, entry.code, entry.resourceId,
      entry.state, entry.severity, entry.currentRevision, entry.reviewedRevision,
      entry.completeCoverage, entry.reasons.join(";"), entry.suggestedAction,
    ].map(escape).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
