import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import {
  canReadWork, WorkInputError, type WorkRole,
} from "./remediation-work-input";
import {
  loadWorkIntegrity, type IntegrityCode, type IntegrityFinding,
} from "./work-integrity";
import {
  TRIAGE_AUDIT_ACTION, TRIAGE_RESOURCE_TYPE, hydrateTriageEvent,
  type TriageDecision, type TriageEvent,
} from "./work-integrity-triage";

/**
 * Case management joins real read-only operational diagnostics to human audit
 * decisions. It never fabricates a diagnostic from a previous human decision,
 * and it never changes remediation, finding, evidence or scoring state.
 */
export type CaseScope = {
  organizationId: string;
  userId: string;
  role: WorkRole;
};
export type CaseState =
  | "UNREVIEWED"
  | "INVESTIGATING"
  | "ACKNOWLEDGED"
  | "DISMISSED"
  | "REOPENED"
  | "STALE"
  | "NO_LONGER_DETECTED";
export const CASE_STATES: readonly CaseState[] = [
  "UNREVIEWED", "INVESTIGATING", "ACKNOWLEDGED", "DISMISSED",
  "REOPENED", "STALE", "NO_LONGER_DETECTED",
];
export type CaseSeverity = "critical" | "attention" | "info";
export type CaseRow = {
  key: string;
  workItemId: string;
  taskStatus: string;
  taskRevision: number;
  resourceId: string;
  code: IntegrityCode;
  severity: CaseSeverity | null;
  diagnostic: string | null;
  recommendation: string | null;
  state: CaseState;
  reviewEventId: string | null;
  reviewedAt: string | null;
  reviewedRevision: number | null;
  reviewerUserId: string | null;
  reviewRationale: string | null;
  reviewReference: string | null;
  completeCoverage: boolean;
  historicalOnly: boolean;
};
export type CaseFilters = {
  state: CaseState | "ALL";
  severity: CaseSeverity | "ALL";
  search: string;
  limit: 10 | 25 | 50 | 100;
  cursor: string | null;
  includeInfo: boolean;
  includeHistorical: boolean;
};
export type CaseSummary = {
  totalOnPage: number;
  unreviewed: number;
  investigating: number;
  acknowledged: number;
  dismissed: number;
  reopened: number;
  stale: number;
  noLongerDetected: number;
  critical: number;
  attention: number;
  informational: number;
  partialCoverage: number;
  reviewed: number;
  historicalOnly: number;
};
export type ReviewAuditRow = {
  id: string;
  organizationId: string;
  resourceId: string | null;
  actorUserId: string | null;
  occurredAt: Date;
  metadata: Prisma.JsonValue | null;
};
export type CaseSourceItem = {
  workItemId: string;
  status: string;
  revision: number;
  complete: boolean;
  findings: IntegrityFinding[];
};
export type CasePageSource = {
  checked: number;
  nextCursor: string | null;
  items: CaseSourceItem[];
  limitations: string[];
};
const MAX_QUERY_LENGTH = 120;
const MAX_EVENTS = 10000;

export function caseKey(workItemId: string, code: IntegrityCode, resourceId: string): string {
  // JSON array avoids ambiguity when IDs include delimiters.
  return JSON.stringify([workItemId, code, resourceId]);
}
export function parseCaseFilters(input: Record<string, unknown>): CaseFilters {
  const state = input.state ?? "ALL";
  if (typeof state !== "string" ||
      (state !== "ALL" && !CASE_STATES.includes(state as CaseState)))
    throw new WorkInputError("INVALID", "Invalid case state.");
  const severity = input.severity ?? "ALL";
  if (!["ALL", "critical", "attention", "info"].includes(String(severity)))
    throw new WorkInputError("INVALID", "Invalid diagnostic severity.");
  const limit = input.limit === undefined ? 25 : Number(input.limit);
  if (![10, 25, 50, 100].includes(limit))
    throw new WorkInputError("INVALID", "Limit must be 10, 25, 50 or 100.");
  const search = input.search === undefined ? "" : input.search;
  if (typeof search !== "string" || search.length > MAX_QUERY_LENGTH ||
      /[\u0000-\u001f\u007f]/.test(search))
    throw new WorkInputError("INVALID", "Search must be bounded printable text.");
  const cursor = input.cursor === undefined || input.cursor === "" ? null : input.cursor;
  if (cursor !== null && (typeof cursor !== "string" || cursor.length > 300))
    throw new WorkInputError("INVALID", "Invalid page cursor.");
  const includeInfo = input.includeInfo === undefined ? false : input.includeInfo === "true";
  const includeHistorical = input.includeHistorical === undefined ? false :
    input.includeHistorical === "true";
  for (const key of ["includeInfo", "includeHistorical"]) {
    if (input[key] !== undefined && !["true", "false"].includes(String(input[key])))
      throw new WorkInputError("INVALID", `Invalid ${key} filter.`);
  }
  return {
    state: state as CaseFilters["state"],
    severity: severity as CaseFilters["severity"],
    limit: limit as CaseFilters["limit"],
    search: search.trim().toLowerCase(),
    cursor: cursor as string | null,
    includeInfo, includeHistorical,
  };
}
export function latestReviewByCase(events: readonly TriageEvent[]): Map<string, TriageEvent> {
  const latest = new Map<string, TriageEvent>();
  for (const event of events) {
    const key = caseKey(event.workItemId, event.code, event.resourceId);
    const current = latest.get(key);
    if (!current || event.occurredAt.getTime() > current.occurredAt.getTime() ||
        (event.occurredAt.getTime() === current.occurredAt.getTime() &&
         event.id.localeCompare(current.id) > 0)) latest.set(key, event);
  }
  return latest;
}
export function stateFromReview(
  decision: TriageDecision | null, reviewedRevision: number | null,
  currentRevision: number, detected: boolean,
): CaseState {
  // A stale decision cannot explain current findings after a work item changed.
  if (decision !== null && reviewedRevision !== currentRevision) return "STALE";
  if (!detected) return "NO_LONGER_DETECTED";
  if (decision === null) return "UNREVIEWED";
  switch (decision) {
    case "INVESTIGATE": return "INVESTIGATING";
    case "ACKNOWLEDGE": return "ACKNOWLEDGED";
    case "DISMISS": return "DISMISSED";
    case "REOPEN": return "REOPENED";
  }
}
function reviewRow(
  item: CaseSourceItem,
  finding: IntegrityFinding | null,
  audit: TriageEvent | null,
): CaseRow {
  if (!finding && !audit) throw new Error("A case requires a signal or review.");
  const code = finding?.code ?? audit!.code;
  const resourceId = finding?.resourceId ?? audit!.resourceId;
  return {
    key: caseKey(item.workItemId, code, resourceId),
    workItemId: item.workItemId,
    taskStatus: item.status,
    taskRevision: item.revision,
    resourceId,
    code,
    severity: finding?.severity ?? null,
    diagnostic: finding?.message ?? null,
    recommendation: finding?.recommendation ?? null,
    state: stateFromReview(audit?.decision ?? null, audit?.revision ?? null,
      item.revision, finding !== null),
    reviewEventId: audit?.id ?? null,
    reviewedAt: audit?.occurredAt.toISOString() ?? null,
    reviewedRevision: audit?.revision ?? null,
    reviewerUserId: audit?.actorUserId ?? null,
    reviewRationale: audit?.rationale ?? null,
    reviewReference: audit?.reference ?? null,
    completeCoverage: item.complete,
    historicalOnly: finding === null,
  };
}
export function combineCasePage(
  source: CasePageSource,
  events: readonly TriageEvent[],
  includeHistorical = false,
): CaseRow[] {
  const latest = latestReviewByCase(events);
  const rows: CaseRow[] = [];
  const seen = new Set<string>();
  for (const item of source.items) {
    for (const finding of item.findings) {
      const key = caseKey(item.workItemId, finding.code, finding.resourceId);
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push(reviewRow(item, finding, latest.get(key) ?? null));
    }
    if (includeHistorical) for (const [key, review] of latest) {
      if (review.workItemId !== item.workItemId || seen.has(key)) continue;
      // Never assert that a diagnostic disappeared on a partial record.
      // Historical-only case is withheld until all linked datasets were read.
      if (!item.complete) continue;
      seen.add(key);
      rows.push(reviewRow(item, null, review));
    }
  }
  return rows;
}
export function filterCaseRows(rows: readonly CaseRow[], filters: CaseFilters): CaseRow[] {
  return rows.filter(row => {
    if (filters.state !== "ALL" && row.state !== filters.state) return false;
    if (filters.severity !== "ALL" && row.severity !== filters.severity) return false;
    if (!filters.includeInfo && row.severity === "info") return false;
    if (filters.search) {
      const haystack = [
        row.workItemId, row.resourceId, row.code, row.diagnostic,
        row.recommendation, row.reviewRationale, row.reviewReference,
      ].filter(Boolean).join(" ").toLowerCase();
      if (!haystack.includes(filters.search)) return false;
    }
    return true;
  });
}
export function caseSummary(rows: readonly CaseRow[]): CaseSummary {
  const result: CaseSummary = {
    totalOnPage: rows.length,
    unreviewed: 0, investigating: 0, acknowledged: 0,
    dismissed: 0, reopened: 0, stale: 0, noLongerDetected: 0,
    critical: 0, attention: 0, informational: 0,
    partialCoverage: 0, reviewed: 0, historicalOnly: 0,
  };
  for (const row of rows) {
    switch (row.state) {
      case "UNREVIEWED": result.unreviewed++; break;
      case "INVESTIGATING": result.investigating++; break;
      case "ACKNOWLEDGED": result.acknowledged++; break;
      case "DISMISSED": result.dismissed++; break;
      case "REOPENED": result.reopened++; break;
      case "STALE": result.stale++; break;
      case "NO_LONGER_DETECTED": result.noLongerDetected++; break;
    }
    if (row.severity === "critical") result.critical++;
    if (row.severity === "attention") result.attention++;
    if (row.severity === "info") result.informational++;
    if (!row.completeCoverage) result.partialCoverage++;
    if (row.reviewEventId !== null) result.reviewed++;
    if (row.historicalOnly) result.historicalOnly++;
  }
  return result;
}
export function priorityOfCase(row: CaseRow): number {
  if (row.state === "STALE") return 0;
  if (row.severity === "critical" && row.state === "UNREVIEWED") return 1;
  if (row.severity === "critical" && row.state === "REOPENED") return 2;
  if (row.state === "UNREVIEWED") return 3;
  if (row.state === "REOPENED") return 4;
  if (row.state === "INVESTIGATING") return 5;
  if (row.state === "ACKNOWLEDGED") return 6;
  if (row.state === "DISMISSED") return 7;
  return 8;
}
export function orderCaseRows(rows: readonly CaseRow[]): CaseRow[] {
  return [...rows].sort((a, b) =>
    priorityOfCase(a) - priorityOfCase(b) ||
    a.workItemId.localeCompare(b.workItemId) ||
    a.code.localeCompare(b.code) ||
    a.resourceId.localeCompare(b.resourceId));
}
export type CasePage = {
  generatedAt: string;
  filters: CaseFilters;
  totalWorkItemsExamined: number;
  cases: CaseRow[];
  summary: CaseSummary;
  nextCursor: string | null;
  reviewEventsFetched: number;
  historyComplete: boolean;
  limitations: string[];
};
/** Read the exact tenant-scoped audit history for the current bounded work page. */
export async function loadIntegrityCases(
  scope: CaseScope, input: Record<string, unknown>, now = new Date(),
): Promise<CasePage> {
  if (!canReadWork(scope.role) || !scope.organizationId || !scope.userId)
    throw new WorkInputError("FORBIDDEN", "Organization membership required.");
  const filters = parseCaseFilters(input);
  // Gather all diagnostic categories before applying case filters: informational
  // history can still be relevant to a later human review.
  const report = await loadWorkIntegrity(scope, {
    limit: String(filters.limit),
    cursor: filters.cursor ?? undefined,
    includeInfo: "true",
  }, now);
  const ids = report.items.map(item => item.workItemId);
  const auditRows = ids.length ? await db.auditEvent.findMany({
    where: {
      organizationId: scope.organizationId,
      resourceId: { in: ids },
      resourceType: TRIAGE_RESOURCE_TYPE,
      action: TRIAGE_AUDIT_ACTION,
    },
    select: {
      id: true, organizationId: true, resourceId: true, actorUserId: true,
      occurredAt: true, metadata: true,
    },
    orderBy: [{ occurredAt: "desc" }, { id: "desc" }],
    take: MAX_EVENTS + 1,
  }) : [];
  const historyComplete = auditRows.length <= MAX_EVENTS;
  // Avoid incorrectly describing a partial event history as authoritative.
  const events = historyComplete
    ? auditRows.map(hydrateTriageEvent).filter((x): x is TriageEvent => x !== null)
    : [];
  const merged = combineCasePage(report, events, filters.includeHistorical && historyComplete);
  const cases = orderCaseRows(filterCaseRows(merged, filters));
  return {
    generatedAt: now.toISOString(),
    filters,
    totalWorkItemsExamined: report.checked,
    cases, summary: caseSummary(cases),
    nextCursor: report.nextCursor,
    reviewEventsFetched: auditRows.length,
    historyComplete,
    limitations: [
      ...report.limitations,
      "Case state is derived only from stored diagnostics and recorded human decisions.",
      "When audit history reaches its 10,000-event limit, review decisions are withheld rather than guessed.",
      "Search and case filters apply after the bounded work-item page is fetched; counts describe only this page.",
      "A dismissed or acknowledged anomaly does not certify compliance or resolve a security finding.",
      "A historical-only case is shown only when the underlying work item's linked data coverage is complete.",
    ],
  };
}
