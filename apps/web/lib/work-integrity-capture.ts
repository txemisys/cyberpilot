import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { parseCaseSnapshot } from "./work-integrity-snapshots";

/**
 * Assemble complete, reproducible organization snapshots from multiple
 * bounded API pages. A collection is never declared complete until all
 * continuation cursors and linked-record coverage have been checked.
 */
export type CasePageCapture = {
  organizationId: string;
  capturedAt: string;
  source: string;
  requestCursor: string | null;
  nextCursor: string | null;
  checkedWorkItems: number;
  cases: CaseRow[];
  historyComplete: boolean;
  limitations: string[];
};
export type CaptureCheckpoint = {
  organizationId: string;
  capturedAt: string;
  source: string;
  pages: CasePageCapture[];
  pendingCursor: string | null;
  finished: boolean;
  rejected: boolean;
  rejectionReasons: string[];
};
export type CaptureProgress = {
  pagesCollected: number;
  workItemsExamined: number;
  caseCount: number;
  distinctWorkItems: number;
  pendingCursor: string | null;
  finished: boolean;
  complete: boolean;
  historyComplete: boolean;
  linkedCoverageComplete: boolean;
  limitations: string[];
};
export type CaptureResult = {
  snapshot: CaseSnapshot;
  progress: CaptureProgress;
  pageBoundaries: Array<{
    page: number;
    cursor: string | null;
    nextCursor: string | null;
    checkedWorkItems: number;
    cases: number;
  }>;
};
export type CaptureOptions = {
  maxPages: number;
  maxCases: number;
  maxWorkItems: number;
  requireCompleteHistory: boolean;
  requireCompleteLinkedRecords: boolean;
};
export const DEFAULT_CAPTURE_OPTIONS: CaptureOptions = {
  maxPages: 100,
  maxCases: 10000,
  maxWorkItems: 10000,
  requireCompleteHistory: true,
  requireCompleteLinkedRecords: true,
};
function assertText(value: unknown, label: string, max: number): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
}
function assertCursor(value: unknown, label: string): asserts value is string | null {
  if (value !== null) assertText(value, label, 300);
}
function assertNonNegativeInteger(value: unknown, label: string, max: number): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new Error(`Invalid ${label}.`);
}
export function validateCaptureOptions(options: CaptureOptions): CaptureOptions {
  assertNonNegativeInteger(options.maxPages, "maximum pages", 10000);
  assertNonNegativeInteger(options.maxCases, "maximum cases", 100000);
  assertNonNegativeInteger(options.maxWorkItems, "maximum work items", 100000);
  if (options.maxPages === 0 || options.maxCases === 0 || options.maxWorkItems === 0)
    throw new Error("Capture bounds must be positive.");
  if (typeof options.requireCompleteHistory !== "boolean" ||
      typeof options.requireCompleteLinkedRecords !== "boolean")
    throw new Error("Invalid completeness policy.");
  return { ...options };
}
export function validateCasePageCapture(page: CasePageCapture): CasePageCapture {
  assertText(page.organizationId, "organization", 256);
  assertText(page.capturedAt, "capture time", 100);
  assertText(page.source, "capture source", 1000);
  if (!Number.isFinite(Date.parse(page.capturedAt)))
    throw new Error("Invalid capture timestamp.");
  assertCursor(page.requestCursor, "request cursor");
  assertCursor(page.nextCursor, "next cursor");
  assertNonNegativeInteger(page.checkedWorkItems, "checked work items", 100000);
  if (typeof page.historyComplete !== "boolean")
    throw new Error("Invalid history completeness.");
  if (!Array.isArray(page.limitations) || page.limitations.length > 100 ||
      page.limitations.some(value => typeof value !== "string" || value.length > 4000))
    throw new Error("Invalid capture limitations.");
  const snapshot = parseCaseSnapshot({
    organizationId: page.organizationId,
    capturedAt: page.capturedAt,
    source: page.source,
    complete: page.historyComplete,
    cases: page.cases,
  });
  if (new Set(snapshot.cases.map(row => row.workItemId)).size > page.checkedWorkItems)
    throw new Error("Page has more case-bearing work items than examined work items.");
  return { ...page, cases: snapshot.cases, limitations: [...page.limitations] };
}
export function startCaseCapture(
  organizationId: string, capturedAt: string, source: string,
): CaptureCheckpoint {
  assertText(organizationId, "organization", 256);
  assertText(source, "source", 1000);
  assertText(capturedAt, "capture time", 100);
  if (!Number.isFinite(Date.parse(capturedAt))) throw new Error("Invalid capture time.");
  return {
    organizationId, capturedAt, source, pages: [],
    pendingCursor: null, finished: false, rejected: false, rejectionReasons: [],
  };
}
export function appendCapturePage(
  checkpoint: CaptureCheckpoint,
  incoming: CasePageCapture,
  options: CaptureOptions = DEFAULT_CAPTURE_OPTIONS,
): CaptureCheckpoint {
  const policy = validateCaptureOptions(options);
  if (checkpoint.rejected) throw new Error("Rejected capture cannot be resumed.");
  if (checkpoint.finished) throw new Error("Finished capture cannot be extended.");
  const page = validateCasePageCapture(incoming);
  if (page.organizationId !== checkpoint.organizationId ||
      page.capturedAt !== checkpoint.capturedAt ||
      page.source !== checkpoint.source)
    throw new Error("Capture page identity does not match the checkpoint.");
  if (page.requestCursor !== checkpoint.pendingCursor)
    throw new Error("Unexpected page cursor; pagination must be contiguous.");
  if (page.nextCursor !== null && page.nextCursor === page.requestCursor)
    throw new Error("Pagination cursor did not advance.");
  if (checkpoint.pages.some(previous =>
    previous.requestCursor === page.requestCursor ||
    (page.nextCursor !== null && previous.requestCursor === page.nextCursor)))
    throw new Error("Pagination cycle detected.");
  const pages = [...checkpoint.pages, page];
  if (pages.length > policy.maxPages)
    throw new Error("Capture exceeds maximum pages.");
  const workItems = pages.reduce((sum, item) => sum + item.checkedWorkItems, 0);
  const cases = pages.flatMap(item => item.cases);
  if (workItems > policy.maxWorkItems || cases.length > policy.maxCases)
    throw new Error("Capture exceeds configured resource bounds.");
  const keys = cases.map(row => row.key);
  if (new Set(keys).size !== keys.length)
    throw new Error("Overlapping pages contain duplicate case identities.");
  const finished = page.nextCursor === null;
  return {
    ...checkpoint,
    pages,
    pendingCursor: page.nextCursor,
    finished,
    rejectionReasons: [],
  };
}
export function captureProgress(
  checkpoint: CaptureCheckpoint,
  options: CaptureOptions = DEFAULT_CAPTURE_OPTIONS,
): CaptureProgress {
  const policy = validateCaptureOptions(options);
  const cases = checkpoint.pages.flatMap(page => page.cases);
  const historyComplete = checkpoint.pages.every(page => page.historyComplete);
  const linkedCoverageComplete = cases.every(row => row.completeCoverage);
  const complete = checkpoint.finished && !checkpoint.rejected &&
    (!policy.requireCompleteHistory || historyComplete) &&
    (!policy.requireCompleteLinkedRecords || linkedCoverageComplete);
  return {
    pagesCollected: checkpoint.pages.length,
    workItemsExamined: checkpoint.pages.reduce((sum, page) => sum + page.checkedWorkItems, 0),
    caseCount: cases.length,
    distinctWorkItems: new Set(cases.map(row => row.workItemId)).size,
    pendingCursor: checkpoint.pendingCursor,
    finished: checkpoint.finished,
    complete,
    historyComplete,
    linkedCoverageComplete,
    limitations: [
      ...new Set(checkpoint.pages.flatMap(page => page.limitations)),
      ...(!checkpoint.finished ? ["More pages are required before collection is complete."] : []),
      ...(!historyComplete ? ["At least one page has incomplete review history."] : []),
      ...(!linkedCoverageComplete ? ["At least one case has incomplete linked-record coverage."] : []),
      ...checkpoint.rejectionReasons,
    ],
  };
}
export function finalizeCaseCapture(
  checkpoint: CaptureCheckpoint,
  options: CaptureOptions = DEFAULT_CAPTURE_OPTIONS,
): CaptureResult {
  if (!checkpoint.finished || checkpoint.rejected)
    throw new Error("Capture must finish without rejection before finalization.");
  const progress = captureProgress(checkpoint, options);
  const snapshot = parseCaseSnapshot({
    organizationId: checkpoint.organizationId,
    source: checkpoint.source,
    capturedAt: checkpoint.capturedAt,
    complete: progress.complete,
    cases: checkpoint.pages.flatMap(page => page.cases),
  }, options.maxCases);
  return {
    snapshot, progress,
    pageBoundaries: checkpoint.pages.map((page, index) => ({
      page: index + 1, cursor: page.requestCursor,
      nextCursor: page.nextCursor,
      checkedWorkItems: page.checkedWorkItems,
      cases: page.cases.length,
    })),
  };
}
export function rejectCaseCapture(
  checkpoint: CaptureCheckpoint, reason: string,
): CaptureCheckpoint {
  assertText(reason, "rejection reason", 1000);
  return {
    ...checkpoint,
    rejected: true,
    rejectionReasons: [...checkpoint.rejectionReasons, reason],
  };
}
export function resumeCapture(
  checkpoint: CaptureCheckpoint,
  options: CaptureOptions = DEFAULT_CAPTURE_OPTIONS,
): CaptureCheckpoint {
  validateCaptureOptions(options);
  if (checkpoint.rejected) throw new Error("Cannot resume a rejected capture.");
  if (checkpoint.pages.length > options.maxPages)
    throw new Error("Checkpoint exceeds configured page bound.");
  let replay = startCaseCapture(
    checkpoint.organizationId, checkpoint.capturedAt, checkpoint.source,
  );
  for (const page of checkpoint.pages) replay = appendCapturePage(replay, page, options);
  if (replay.finished !== checkpoint.finished ||
      replay.pendingCursor !== checkpoint.pendingCursor)
    throw new Error("Checkpoint pagination metadata is inconsistent.");
  return replay;
}
export function captureCheckpointJson(checkpoint: CaptureCheckpoint): string {
  const checked = checkpoint.rejected ? checkpoint : resumeCapture(checkpoint);
  return JSON.stringify(checked, null, 2) + "\n";
}
export function parseCaptureCheckpointJson(
  text: string, expectedOrganizationId: string,
  options: CaptureOptions = DEFAULT_CAPTURE_OPTIONS,
): CaptureCheckpoint {
  if (typeof text !== "string" || text.length > 10_000_000)
    throw new Error("Checkpoint exceeds the input size limit.");
  let raw: unknown;
  try { raw = JSON.parse(text); }
  catch { throw new Error("Checkpoint JSON is invalid."); }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw))
    throw new Error("Invalid checkpoint object.");
  const item = raw as Record<string, unknown>;
  if (item.organizationId !== expectedOrganizationId)
    throw new Error("Checkpoint organization mismatch.");
  if (!Array.isArray(item.pages))
    throw new Error("Invalid checkpoint pages.");
  const start = startCaseCapture(
    item.organizationId as string,
    item.capturedAt as string,
    item.source as string,
  );
  let result = start;
  for (const page of item.pages) {
    result = appendCapturePage(result, page as CasePageCapture, options);
  }
  if (item.finished !== result.finished || item.pendingCursor !== result.pendingCursor)
    throw new Error("Checkpoint status mismatch.");
  if (item.rejected === true) {
    if (!Array.isArray(item.rejectionReasons) ||
        item.rejectionReasons.some(x => typeof x !== "string" || !x.trim()))
      throw new Error("Invalid rejection reasons.");
    for (const reason of item.rejectionReasons as string[])
      result = rejectCaseCapture(result, reason);
  } else if (item.rejected !== false) throw new Error("Invalid rejection flag.");
  return result;
}
export type CaptureCoverageAudit = {
  capturedCases: number;
  casesWithIncompleteLinkedData: number;
  incompletePages: number;
  pendingPages: boolean;
  duplicateWorkItemPages: string[];
  complete: boolean;
};
export function auditCaptureCoverage(checkpoint: CaptureCheckpoint): CaptureCoverageAudit {
  const counts = new Map<string, number>();
  for (const page of checkpoint.pages) {
    for (const workItemId of new Set(page.cases.map(row => row.workItemId)))
      counts.set(workItemId, (counts.get(workItemId) ?? 0) + 1);
  }
  const duplicateWorkItemPages = [...counts.entries()]
    .filter(([, count]) => count > 1).map(([id]) => id).sort();
  const progress = captureProgress(checkpoint);
  return {
    capturedCases: progress.caseCount,
    casesWithIncompleteLinkedData: checkpoint.pages.flatMap(page => page.cases)
      .filter(row => !row.completeCoverage).length,
    incompletePages: checkpoint.pages.filter(page => !page.historyComplete).length,
    pendingPages: !checkpoint.finished,
    duplicateWorkItemPages,
    complete: progress.complete && duplicateWorkItemPages.length === 0,
  };
}
