import type { CaseScope, CasePage, CaseRow } from "./work-integrity-cases";
import { loadIntegrityCases } from "./work-integrity-cases";
import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";

/**
 * Read-only bounded traversal of real tenant-scoped work-item pages.
 * A capture is complete only if all requested pages are read, all linked
 * records and audit histories are complete, and no source cursor remains.
 */
export type CaptureTraversalOptions = {
  maxPages: number;
  pageSize: 10 | 25 | 50 | 100;
  includeHistorical: boolean;
  includeInfo: boolean;
};
export type CaptureTraversalResult = {
  snapshot: CaseSnapshot;
  pagesRead: number;
  workItemsExamined: number;
  casesCollected: number;
  hasMore: boolean;
  nextCursor: string | null;
  historyComplete: boolean;
  linkedCoverageComplete: boolean;
  duplicateCases: number;
  warnings: string[];
};
export const DEFAULT_CAPTURE_TRAVERSAL: CaptureTraversalOptions = {
  maxPages: 5,
  pageSize: 50,
  includeHistorical: true,
  includeInfo: true,
};
export function parseCaptureTraversalOptions(
  raw: Record<string, unknown>,
): CaptureTraversalOptions {
  const accepted = new Set(["maxPages", "pageSize", "includeHistorical", "includeInfo"]);
  for (const key of Object.keys(raw)) {
    if (!accepted.has(key))
      throw new Error("Unsupported full-capture option.");
  }
  const integer = (value: unknown, fallback: number, values: readonly number[]) => {
    if (value === undefined) return fallback;
    if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value))
      throw new Error("Invalid full-capture numeric option.");
    const number = Number(value);
    if (!values.includes(number))
      throw new Error("Full-capture numeric option exceeds allowed bounds.");
    return number;
  };
  const bool = (value: unknown, fallback: boolean) => {
    if (value === undefined) return fallback;
    if (value === "true") return true;
    if (value === "false") return false;
    throw new Error("Invalid full-capture boolean option.");
  };
  return {
    maxPages: integer(raw.maxPages, 5, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    pageSize: integer(raw.pageSize, 50, [10, 25, 50, 100]) as
      CaptureTraversalOptions["pageSize"],
    includeHistorical: bool(raw.includeHistorical, true),
    includeInfo: bool(raw.includeInfo, true),
  };
}
export async function traverseIntegrityCapture(
  scope: CaseScope,
  options: CaptureTraversalOptions = DEFAULT_CAPTURE_TRAVERSAL,
  load: typeof loadIntegrityCases = loadIntegrityCases,
): Promise<CaptureTraversalResult> {
  if (!scope.organizationId || !scope.userId)
    throw new Error("A trusted authenticated work scope is required.");
  if (!Number.isSafeInteger(options.maxPages) ||
      options.maxPages < 1 || options.maxPages > 10 ||
      ![10, 25, 50, 100].includes(options.pageSize))
    throw new Error("Invalid bounded traversal policy.");
  const allCases = new Map<string, CaseRow>();
  const seenCursors = new Set<string>();
  let nextCursor: string | null = null;
  let pagesRead = 0;
  let workItemsExamined = 0;
  let duplicateCases = 0;
  let historyComplete = true;
  let linkedCoverageComplete = true;
  let sourceTime: string | null = null;
  const warnings: string[] = [];
  for (let index = 0; index < options.maxPages; index++) {
    const input: Record<string, unknown> = {
      limit: String(options.pageSize),
      includeInfo: String(options.includeInfo),
      includeHistorical: String(options.includeHistorical),
    };
    if (nextCursor !== null) input.cursor = nextCursor;
    const page: CasePage = await load(scope, input);
    pagesRead++;
    workItemsExamined += page.totalWorkItemsExamined;
    if (!sourceTime) sourceTime = page.generatedAt;
    historyComplete = historyComplete && page.historyComplete;
    linkedCoverageComplete = linkedCoverageComplete &&
      page.cases.every(row => row.completeCoverage);
    for (const row of page.cases) {
      if (allCases.has(row.key)) {
        duplicateCases++;
        // Never silently overwrite conflicting records encountered on
        // separate cursor pages; they can indicate concurrent updates.
        const existing = allCases.get(row.key)!;
        if (JSON.stringify(existing) !== JSON.stringify(row))
          throw new Error("Conflicting case records encountered across capture pages.");
      } else {
        allCases.set(row.key, row);
      }
    }
    warnings.push(...page.limitations);
    const following = page.nextCursor;
    if (following === null) {
      nextCursor = null;
      break;
    }
    if (seenCursors.has(following))
      throw new Error("Repeated work-item cursor; capture traversal stopped.");
    seenCursors.add(following);
    nextCursor = following;
  }
  const hasMore = nextCursor !== null;
  const complete = !hasMore && historyComplete && linkedCoverageComplete &&
    options.includeHistorical && options.includeInfo;
  const source = JSON.stringify({
    kind: "tenant-scoped-multi-page-case-capture",
    pageSize: options.pageSize,
    includeHistorical: options.includeHistorical,
    includeInfo: options.includeInfo,
    firstCursor: null,
  });
  const snapshot = parseCaseSnapshot({
    organizationId: scope.organizationId,
    capturedAt: sourceTime ?? new Date(0).toISOString(),
    source,
    complete,
    cases: [...allCases.values()].sort((a, b) => a.key.localeCompare(b.key)),
  }, 10000);
  return {
    snapshot, pagesRead, workItemsExamined,
    casesCollected: snapshot.cases.length,
    hasMore, nextCursor, historyComplete,
    linkedCoverageComplete, duplicateCases,
    warnings: [
      ...new Set(warnings),
      ...(hasMore ? [
        "Capture stopped at the configured page limit. Additional work items exist.",
      ] : []),
      ...(!historyComplete ? [
        "At least one page had incomplete audit history; review conclusions are not authoritative.",
      ] : []),
      ...(!linkedCoverageComplete ? [
        "At least one case had incomplete linked-record coverage.",
      ] : []),
      ...(duplicateCases ? [
        "Duplicate case identities were deduplicated across cursor pages.",
      ] : []),
      "This is a bounded, sequential capture; concurrent updates may affect consistency.",
      "A complete traversal is not an independently authenticated security assessment.",
    ],
  };
}
