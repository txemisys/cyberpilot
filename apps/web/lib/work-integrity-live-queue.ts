import type { CasePage } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist, filterReviewWorklist, groupReviewBatches, type ReviewPriority } from "./work-integrity-worklist";
import { caseDimensions, groupCases } from "./work-integrity-analytics";
import { buildEvidenceReadiness, evidenceReviewQueue, type EvidenceRequirement } from "./work-integrity-evidence-readiness";

/**
 * Converts a tenant-scoped, live, bounded case page into actionable analyst
 * information. This does not claim organization-wide completeness.
 */
export const LIVE_EVIDENCE_REQUIREMENTS: EvidenceRequirement[] = [{
  id: "recorded-human-review",
  diagnosticCodes: [],
  mandatoryFields: ["reviewEventId", "reviewRationale", "reviewedAt"],
  requireCurrentRevision: true,
  requireCompleteCoverage: true,
  requireHumanReview: true,
}];
export type LiveIntegrityFilters = {
  priority: ReviewPriority | "ALL";
  reviewed: "ALL" | "YES" | "NO";
  offset: number;
  pageSize: number;
};
export type LiveIntegrityPage = {
  organizationId: string;
  capturedAt: string;
  snapshotComplete: boolean;
  workItemsExamined: number;
  historyComplete: boolean;
  nextWorkCursor: string | null;
  totalCasesOnWorkPage: number;
  totalMatching: number;
  nextOffset: number | null;
  offset: number;
  pageSize: number;
  priorities: Record<ReviewPriority, number>;
  reviewReasons: Record<string, number>;
  metrics: ReturnType<typeof caseDimensions>;
  evidence: {
    total: number;
    ready: number;
    blocked: number;
    missingReview: number;
    staleReview: number;
    incompleteCoverage: number;
  };
  groups: Array<{ code: string; count: number; critical: number; stale: number; incompleteCoverage: number }>;
  batches: Array<{ id: string; priority: ReviewPriority; count: number; completeCoverage: boolean; requiresReassessment: boolean }>;
  entries: Array<{
    caseKey: string;
    workItemId: string;
    code: string;
    resourceId: string;
    priority: ReviewPriority;
    state: string;
    reasons: string[];
    suggestedAction: string;
    completeCoverage: boolean;
    evidenceReady: boolean;
    missingEvidence: string[];
    reviewEventId: string | null;
  }>;
  limitations: string[];
};
function strictNumber(value: unknown, fallback: number, maximum: number, minimum = 0): number {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value))
    throw new Error("Invalid analyst queue pagination.");
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum)
    throw new Error("Analyst queue pagination is outside permitted bounds.");
  return number;
}
export function parseLiveIntegrityFilters(
  input: Record<string, unknown>,
): LiveIntegrityFilters {
  const priority = input.priority ?? "ALL";
  const reviewed = input.reviewed ?? "ALL";
  if (!["ALL", "P0", "P1", "P2", "P3", "P4"].includes(priority as string))
    throw new Error("Invalid review priority.");
  if (!["ALL", "YES", "NO"].includes(reviewed as string))
    throw new Error("Invalid reviewed filter.");
  return {
    priority: priority as LiveIntegrityFilters["priority"],
    reviewed: reviewed as LiveIntegrityFilters["reviewed"],
    offset: strictNumber(input.offset, 0, 100000),
    pageSize: strictNumber(input.pageSize, 25, 100, 1),
  };
}
export function casePageSnapshot(
  organizationId: string, page: CasePage,
): CaseSnapshot {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Invalid organization identity.");
  // A single cursor page is not an organization-wide capture. Even when the
  // page has no next cursor, preceding pages may not have been inspected.
  const complete = page.nextCursor === null && !page.filters.cursor &&
    page.historyComplete && page.filters.state === "ALL" &&
    page.filters.severity === "ALL" && !page.filters.search &&
    page.filters.includeInfo && page.filters.includeHistorical &&
    page.cases.every(row => row.completeCoverage);
  return parseCaseSnapshot({
    organizationId, capturedAt: page.generatedAt,
    source: "tenant-scoped-live-case-page",
    complete, cases: page.cases,
  });
}
export function buildLiveIntegrityPage(
  organizationId: string,
  page: CasePage,
  input: Record<string, unknown> = {},
): LiveIntegrityPage {
  const filters = parseLiveIntegrityFilters(input);
  const snapshot = casePageSnapshot(organizationId, page);
  const queue = buildReviewWorklist(snapshot);
  const evidence = buildEvidenceReadiness(snapshot, LIVE_EVIDENCE_REQUIREMENTS);
  const evidenceByKey = new Map(evidence.packets.map(packet => [packet.caseKey, packet]));
  const filtered = filterReviewWorklist(queue, {
    ...(filters.priority === "ALL" ? {} : { priorities: [filters.priority] }),
    ...(filters.reviewed === "ALL" ? {} : { includeReviewed: filters.reviewed === "YES" }),
    offset: filters.offset, limit: filters.pageSize,
  });
  const batches = groupReviewBatches(queue, 25);
  return {
    organizationId, capturedAt: snapshot.capturedAt,
    snapshotComplete: snapshot.complete,
    workItemsExamined: page.totalWorkItemsExamined,
    historyComplete: page.historyComplete,
    nextWorkCursor: page.nextCursor,
    totalCasesOnWorkPage: queue.total,
    totalMatching: filtered.totalMatching,
    nextOffset: filtered.nextOffset,
    offset: filtered.offset, pageSize: filtered.limit,
    priorities: queue.byPriority, reviewReasons: queue.byReason,
    metrics: caseDimensions(snapshot.cases),
    evidence: {
      total: evidence.total, ready: evidence.ready, blocked: evidence.blocked,
      missingReview: evidence.missingReview, staleReview: evidence.staleReview,
      incompleteCoverage: evidence.incompleteCoverage,
    },
    groups: groupCases(snapshot.cases, "code").map(group => ({
      code: group.key, count: group.count, critical: group.critical,
      stale: group.stale, incompleteCoverage: group.incompleteCoverage,
    })),
    batches: batches.map(batch => ({
      id: batch.batchId, priority: batch.priority,
      count: batch.entries.length, completeCoverage: batch.completeCoverage,
      requiresReassessment: batch.requiresReassessment,
    })),
    entries: filtered.entries.map(entry => {
      const packet = evidenceByKey.get(entry.caseKey);
      return {
        caseKey: entry.caseKey, workItemId: entry.workItemId,
        code: entry.code, resourceId: entry.resourceId,
        priority: entry.priority, state: entry.state,
        reasons: entry.reasons, suggestedAction: entry.suggestedAction,
        completeCoverage: entry.completeCoverage,
        evidenceReady: packet?.readyForHumanReview ?? false,
        missingEvidence: [...new Set(packet?.gaps.map(gap => gap.field) ?? ["missingPacket"])].sort(),
        reviewEventId: entry.reviewEventId,
      };
    }),
    limitations: [
      ...page.limitations,
      ...queue.limitations,
      "Counts and filters refer only to the selected bounded work-item cursor page.",
      "Readiness means recorded evidence fields exist; it does not authenticate them.",
      "A page without a continuation cursor is not proof that other cursor pages were reviewed.",
      "No review, assignment, remediation, or security verification is performed by this view.",
    ],
  };
}
export function liveIntegrityCsv(report: LiveIntegrityPage): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const lines = [["caseKey", "workItemId", "code", "resourceId", "priority",
    "state", "reasons", "completeCoverage", "evidenceReady", "missingEvidence",
    "reviewEventId", "suggestedAction"].map(safe).join(",")];
  for (const entry of report.entries) {
    lines.push([entry.caseKey, entry.workItemId, entry.code,
      entry.resourceId, entry.priority, entry.state, entry.reasons.join(";"),
      entry.completeCoverage, entry.evidenceReady, entry.missingEvidence.join(";"),
      entry.reviewEventId, entry.suggestedAction].map(safe).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
