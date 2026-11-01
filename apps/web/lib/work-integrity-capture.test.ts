import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import {
  DEFAULT_CAPTURE_OPTIONS, validateCaptureOptions, validateCasePageCapture,
  startCaseCapture, appendCapturePage, captureProgress, finalizeCaseCapture,
  rejectCaseCapture, resumeCapture, captureCheckpointJson,
  parseCaptureCheckpointJson, auditCaptureCoverage,
} from "./work-integrity-capture";
import {
  worklistEntry, buildReviewWorklist, filterReviewWorklist, groupReviewBatches,
  compareReviewWorklists, reviewWorklistOverview, reviewWorklistCsv,
} from "./work-integrity-worklist";

function row(id: string, overrides: Partial<CaseRow> = {}): CaseRow {
  return {
    key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
    workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
    taskStatus: "DONE", taskRevision: 1, severity: "attention",
    diagnostic: "No completion timestamp", recommendation: "Review task",
    state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
    reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
    reviewReference: null, completeCoverage: true, historicalOnly: false,
    ...overrides,
  };
}
const first = row("task-1");
const second = row("task-2", { state: "STALE", severity: "critical",
  reviewEventId: "review-2", reviewedRevision: 1, taskRevision: 2 });
const third = row("task-3", { state: "INVESTIGATING", severity: "info",
  reviewEventId: "review-3" });
const historical = row("task-4", { state: "NO_LONGER_DETECTED", severity: null,
  historicalOnly: true, reviewEventId: "review-4" });
const partial = row("task-5", { completeCoverage: false });
const snapshot = (rows: CaseRow[], complete = true, capturedAt = "2026-10-31T10:00:00.000Z") =>
  parseCaseSnapshot({
    organizationId: "org-1", source: "case-api", capturedAt, complete, cases: rows,
  });
const captureTime = "2026-10-31T10:00:00.000Z";
const page = (rows: CaseRow[], requestCursor: string | null = null,
  nextCursor: string | null = null, historyComplete = true) => ({
  organizationId: "org-1", capturedAt: captureTime, source: "case-api",
  requestCursor, nextCursor, checkedWorkItems: rows.length,
  cases: rows, historyComplete, limitations: [] as string[],
});
const start = () => startCaseCapture("org-1", captureTime, "case-api");
describe("capture option validation", () => {
  it("accepts default policy", () => expect(validateCaptureOptions(DEFAULT_CAPTURE_OPTIONS).maxPages).toBe(100));
  it.each(["maxPages", "maxCases", "maxWorkItems"] as const)(
    "rejects zero %s", key => {
      expect(() => validateCaptureOptions({ ...DEFAULT_CAPTURE_OPTIONS, [key]: 0 })).toThrow();
    },
  );
  it("rejects noninteger bounds", () => {
    expect(() => validateCaptureOptions({ ...DEFAULT_CAPTURE_OPTIONS, maxPages: 1.5 })).toThrow();
  });
  it("rejects invalid flags", () => {
    expect(() => validateCaptureOptions({
      ...DEFAULT_CAPTURE_OPTIONS, requireCompleteHistory: "yes" as never,
    })).toThrow();
  });
});
describe("page capture validation", () => {
  it("accepts valid page", () => expect(validateCasePageCapture(page([first])).cases).toHaveLength(1));
  it("rejects mismatched checked count", () => {
    expect(() => validateCasePageCapture({ ...page([first]), checkedWorkItems: 0 })).toThrow();
  });
  it("rejects invalid timestamps", () => {
    expect(() => validateCasePageCapture({ ...page([]), capturedAt: "bad" })).toThrow();
  });
  it("rejects empty organization", () => {
    expect(() => validateCasePageCapture({ ...page([]), organizationId: "" })).toThrow();
  });
  it("rejects invalid history flag", () => {
    expect(() => validateCasePageCapture({ ...page([]), historyComplete: 1 as never })).toThrow();
  });
  it("rejects invalid cursor", () => {
    expect(() => validateCasePageCapture({ ...page([]), nextCursor: "" })).toThrow();
  });
  it("rejects invalid limitations", () => {
    expect(() => validateCasePageCapture({ ...page([]), limitations: [123] as never })).toThrow();
  });
});
describe("bounded capture pagination", () => {
  it("starts empty", () => {
    expect(start().pages).toEqual([]);
    expect(start().pendingCursor).toBeNull();
  });
  it("accepts a single complete page", () => {
    const completed = appendCapturePage(start(), page([first]));
    expect(completed.finished).toBe(true);
    expect(finalizeCaseCapture(completed).snapshot.cases).toHaveLength(1);
  });
  it("collects two contiguous pages", () => {
    const one = appendCapturePage(start(), page([first], null, "next-1"));
    const two = appendCapturePage(one, page([second], "next-1"));
    expect(two.finished).toBe(true);
    expect(finalizeCaseCapture(two).snapshot.cases).toHaveLength(2);
    expect(captureProgress(two).workItemsExamined).toBe(2);
  });
  it("rejects out of order page cursors", () => {
    expect(() => appendCapturePage(start(), page([first], "unexpected"))).toThrow();
  });
  it("rejects nonadvancing cursor", () => {
    const one = appendCapturePage(start(), page([first], null, "next"));
    expect(() => appendCapturePage(one, page([second], "next", "next"))).toThrow();
  });
  it("rejects repeated cursor cycle", () => {
    const one = appendCapturePage(start(), page([first], null, "next"));
    expect(() => appendCapturePage(one, page([second], "next", "next"))).toThrow();
  });
  it("rejects duplicate case keys across pages", () => {
    const one = appendCapturePage(start(), page([first], null, "next"));
    expect(() => appendCapturePage(one, page([first], "next"))).toThrow();
  });
  it("rejects mismatched tenant", () => {
    expect(() => appendCapturePage(start(), { ...page([]), organizationId: "other" })).toThrow();
  });
  it("rejects mismatched capture time", () => {
    expect(() => appendCapturePage(start(), { ...page([]), capturedAt: "2026-10-30T10:00:00.000Z" })).toThrow();
  });
  it("rejects mismatched source", () => {
    expect(() => appendCapturePage(start(), { ...page([]), source: "other" })).toThrow();
  });
  it("rejects excess page count", () => {
    const one = appendCapturePage(start(), page([first], null, "next"));
    expect(() => appendCapturePage(one, page([second], "next"), {
      ...DEFAULT_CAPTURE_OPTIONS, maxPages: 1,
    })).toThrow();
  });
  it("rejects excess case count", () => {
    expect(() => appendCapturePage(start(), page([first, second]), {
      ...DEFAULT_CAPTURE_OPTIONS, maxCases: 1,
    })).toThrow();
  });
  it("rejects excess work item count", () => {
    expect(() => appendCapturePage(start(), page([first, second]), {
      ...DEFAULT_CAPTURE_OPTIONS, maxWorkItems: 1,
    })).toThrow();
  });
  it("rejects adding after completion", () => {
    const complete = appendCapturePage(start(), page([first]));
    expect(() => appendCapturePage(complete, page([]))).toThrow();
  });
  it("rejects adding after rejection", () => {
    const rejected = rejectCaseCapture(start(), "operator cancelled");
    expect(() => appendCapturePage(rejected, page([]))).toThrow();
  });
  it("refuses finalization while pages remain", () => {
    const one = appendCapturePage(start(), page([first], null, "next"));
    expect(() => finalizeCaseCapture(one)).toThrow();
  });
  it("marks incomplete audit history", () => {
    const done = appendCapturePage(start(), page([first], null, null, false));
    expect(captureProgress(done).historyComplete).toBe(false);
    expect(finalizeCaseCapture(done).snapshot.complete).toBe(false);
  });
  it("marks incomplete linked coverage", () => {
    const done = appendCapturePage(start(), page([partial]));
    expect(captureProgress(done).linkedCoverageComplete).toBe(false);
    expect(finalizeCaseCapture(done).snapshot.complete).toBe(false);
  });
  it("respects relaxed history policy", () => {
    const done = appendCapturePage(start(), page([first], null, null, false));
    const relaxed = { ...DEFAULT_CAPTURE_OPTIONS, requireCompleteHistory: false };
    expect(finalizeCaseCapture(done, relaxed).snapshot.complete).toBe(true);
  });
  it("reports boundaries", () => {
    const done = appendCapturePage(start(), page([first]));
    expect(finalizeCaseCapture(done).pageBoundaries[0]?.page).toBe(1);
  });
  it("audits incomplete pages", () => {
    const done = appendCapturePage(start(), page([first], null, null, false));
    expect(auditCaptureCoverage(done).incompletePages).toBe(1);
  });
  it("audits linked coverage", () => {
    const done = appendCapturePage(start(), page([partial]));
    expect(auditCaptureCoverage(done).casesWithIncompleteLinkedData).toBe(1);
  });
  it("supports resumable checkpoints", () => {
    const one = appendCapturePage(start(), page([first], null, "next"));
    expect(resumeCapture(one).pendingCursor).toBe("next");
  });
  it("roundtrips checkpoint JSON", () => {
    const done = appendCapturePage(start(), page([first]));
    expect(parseCaptureCheckpointJson(captureCheckpointJson(done), "org-1").finished).toBe(true);
  });
  it("rejects cross-tenant checkpoint import", () => {
    expect(() => parseCaptureCheckpointJson(captureCheckpointJson(start()), "other")).toThrow();
  });
  it("rejects malformed checkpoint JSON", () => {
    expect(() => parseCaptureCheckpointJson("{", "org-1")).toThrow();
  });
  it("rejects checkpoint metadata tampering", () => {
    const done = appendCapturePage(start(), page([first]));
    expect(() => parseCaptureCheckpointJson(JSON.stringify({
      ...done, pendingCursor: "wrong",
    }), "org-1")).toThrow();
  });
  it("rejects oversized checkpoint import", () => {
    expect(() => parseCaptureCheckpointJson("x".repeat(10_000_001), "org-1")).toThrow();
  });
});
describe("analyst review worklists", () => {
  const current = snapshot([first, second, third, historical, partial]);
  const worklist = buildReviewWorklist(current);
  it("creates one entry per case", () => expect(worklist.entries).toHaveLength(5));
  it("puts stale reviews in highest priority", () => {
    expect(worklistEntry(second).priority).toBe("P0");
  });
  it("prioritizes incomplete coverage", () => {
    expect(worklistEntry(partial).priority).toBe("P1");
  });
  it("preserves reviewer metadata", () => {
    expect(worklistEntry(second).reviewEventId).toBe("review-2");
  });
  it("recommends revision reassessment", () => {
    expect(worklistEntry(second).suggestedAction).toContain("Reassess");
  });
  it("labels historical cases", () => {
    expect(worklistEntry(historical).reasons).toContain("HISTORICAL");
  });
  it("counts all priority buckets", () => {
    expect(Object.values(worklist.byPriority).reduce((a, b) => a + b, 0)).toBe(5);
  });
  it("counts reasons", () => {
    expect(worklist.byReason.STALE_REVIEW).toBe(1);
  });
  it("filters priority", () => {
    expect(filterReviewWorklist(worklist, { priorities: ["P0"] }).entries).toHaveLength(1);
  });
  it("filters reason", () => {
    expect(filterReviewWorklist(worklist, { reasons: ["HISTORICAL"] }).entries).toHaveLength(1);
  });
  it("filters work item", () => {
    expect(filterReviewWorklist(worklist, { workItemIds: ["task-3"] }).entries).toHaveLength(1);
  });
  it("filters diagnostic code", () => {
    expect(filterReviewWorklist(worklist, { codes: ["UNKNOWN"] }).entries).toHaveLength(0);
  });
  it("excludes reviewed cases", () => {
    expect(filterReviewWorklist(worklist, { includeReviewed: false }).entries).toHaveLength(2);
  });
  it("supports pagination", () => {
    const page = filterReviewWorklist(worklist, { limit: 2, offset: 0 });
    expect(page.entries).toHaveLength(2);
    expect(page.nextOffset).toBe(2);
  });
  it("supports final page", () => {
    const page = filterReviewWorklist(worklist, { limit: 2, offset: 4 });
    expect(page.entries).toHaveLength(1);
    expect(page.nextOffset).toBeNull();
  });
  it("rejects invalid pagination", () => {
    expect(() => filterReviewWorklist(worklist, { limit: 0 })).toThrow();
  });
  it("creates bounded batches", () => {
    expect(groupReviewBatches(worklist, 1)).toHaveLength(5);
  });
  it("rejects invalid batch sizes", () => {
    expect(() => groupReviewBatches(worklist, 0)).toThrow();
  });
  it("reports stale review batch", () => {
    expect(groupReviewBatches(worklist).some(batch => batch.requiresReassessment)).toBe(true);
  });
  it("calculates overview", () => {
    expect(reviewWorklistOverview(current).distinctWorkItems).toBe(5);
  });
  it("exports CSV with line endings", () => {
    expect(reviewWorklistCsv(worklist)).toContain("\r\n");
  });
  it("neutralizes formula cells", () => {
    const formula = row("=HYPERLINK", {
      key: JSON.stringify(["=HYPERLINK", "DONE_WITHOUT_COMPLETION", "=HYPERLINK"]),
    });
    expect(reviewWorklistCsv(buildReviewWorklist(snapshot([formula])))).toContain("'=HYPERLINK");
  });
  it("detects escalation", () => {
    const old = snapshot([first]);
    const updated = snapshot([row("task-1", { severity: "critical" })],
      true, "2026-10-31T11:00:00.000Z");
    expect(compareReviewWorklists(old, updated).escalations).toBe(1);
  });
  it("detects deescalation", () => {
    const old = snapshot([row("task-1", { severity: "critical" })]);
    const updated = snapshot([first], true, "2026-10-31T11:00:00.000Z");
    expect(compareReviewWorklists(old, updated).deescalations).toBe(1);
  });
  it("withholds missing-case comparisons under incomplete coverage", () => {
    const old = snapshot([first]);
    const updated = snapshot([], false, "2026-10-31T11:00:00.000Z");
    expect(compareReviewWorklists(old, updated).indeterminate).toBe(1);
  });
  it("rejects cross-tenant comparisons", () => {
    const old = snapshot([first]);
    expect(() => compareReviewWorklists(old, { ...old, organizationId: "other" })).toThrow();
  });
});
