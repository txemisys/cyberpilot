import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

const base: CaseRow = {
  key: JSON.stringify(["work-123", "DONE_WITHOUT_COMPLETION", "work-123"]),
  workItemId: "work-123",
  taskStatus: "DONE",
  taskRevision: 3,
  resourceId: "work-123",
  code: "DONE_WITHOUT_COMPLETION",
  severity: "attention",
  diagnostic: "Missing completion evidence",
  recommendation: "Recheck signed completion event",
  state: "UNREVIEWED",
  reviewEventId: null,
  reviewedAt: null,
  reviewedRevision: null,
  reviewerUserId: null,
  reviewRationale: null,
  reviewReference: null,
  completeCoverage: true,
  historicalOnly: false,
};
const snapshot = (
  rows: CaseRow[] = [base],
  complete = true,
): CaseSnapshot => ({
  organizationId: "org-123",
  capturedAt: "2026-10-31T14:00:00.000Z",
  source: "tenant-scoped-capture",
  complete,
  cases: rows,
});
const review = (patch: Partial<CaseRow> = {}): CaseRow => ({
  ...base,
  state: "INVESTIGATING",
  reviewedAt: "2026-10-31T13:30:00.000Z",
  reviewedRevision: 3,
  reviewEventId: "audit-123",
  reviewerUserId: "user-123",
  reviewRationale: "Evidence requires follow-up",
  ...patch,
});
const issues = (row: CaseRow) =>
  inspectCaptureQuality(snapshot([row])).issues.map(issue => issue.code);

describe("integrity snapshot quality assurance", () => {
  it("does not confuse a clean imported structure with source authentication", () => {
    const result = inspectCaptureQuality(snapshot());
    expect(result.structurallyConsistent).toBe(true);
    expect(result.safeToTreatAsComplete).toBe(true);
    expect(result.blockers).toBe(0);
    expect(result.warnings).toBe(0);
    expect(result.limitations.join(" ")).toMatch(/cannot authenticate/);
  });
  it("never upgrades an explicitly incomplete capture", () => {
    expect(inspectCaptureQuality(snapshot([base], false)).safeToTreatAsComplete).toBe(false);
  });
  it("identifies incomplete linked records", () => {
    const result = inspectCaptureQuality(snapshot([{ ...base, completeCoverage: false }]));
    expect(result.byCode.PARTIAL_CASE_COVERAGE).toBe(1);
    expect(result.byCode.DECLARED_COMPLETE_WITH_PARTIAL_CASES).toBe(1);
    expect(result.safeToTreatAsComplete).toBe(false);
  });
  it("rejects historical-only rows carrying active diagnostics", () => {
    expect(issues(review({ historicalOnly: true }))).toContain("HISTORICAL_WITH_DIAGNOSTIC");
  });
  it("requires review history for historical-only rows", () => {
    expect(issues({ ...base, historicalOnly: true, diagnostic: null }))
      .toContain("HISTORICAL_WITHOUT_REVIEW");
  });
  it("flags active diagnostics with no explanation", () => {
    expect(issues({ ...base, diagnostic: null })).toContain("ACTIVE_WITHOUT_DIAGNOSTIC");
  });
  it("requires event identity on reviewing states", () => {
    expect(issues({ ...base, state: "INVESTIGATING" })).toContain("REVIEW_WITHOUT_EVENT");
  });
  it("requires event time when an event is present", () => {
    expect(issues(review({ reviewedAt: null }))).toContain("EVENT_WITHOUT_REVIEW_TIME");
  });
  it("distinguishes deleted actors from missing events", () => {
    const result = issues(review({ reviewerUserId: null }));
    expect(result).toContain("REVIEW_WITHOUT_ACTOR");
    expect(result).not.toContain("REVIEW_WITHOUT_EVENT");
  });
  it("rejects a review pointing to a future task revision", () => {
    expect(issues(review({ reviewedRevision: 4 }))).toContain("REVIEW_REVISION_IN_FUTURE");
  });
  it("rejects stale label when revision is current", () => {
    expect(issues(review({ state: "STALE" }))).toContain("STALE_REVIEW_REVISION_MATCHES");
  });
  it("rejects a current review label pointing to an old revision", () => {
    expect(issues(review({ reviewedRevision: 2 })))
      .toContain("CURRENT_REVIEW_REVISION_DIFFERS");
  });
  it("accepts an explicitly stale review referencing an older revision", () => {
    const codes = issues(review({ reviewedRevision: 2, state: "STALE" }));
    expect(codes).not.toContain("CURRENT_REVIEW_REVISION_DIFFERS");
    expect(codes).not.toContain("STALE_REVIEW_REVISION_MATCHES");
  });
  it("does not assert a missing diagnostic was resolved", () => {
    expect(issues(review({ state: "NO_LONGER_DETECTED" })))
      .toContain("NO_LONGER_DETECTED_WITH_DIAGNOSTIC");
  });
  it("accepts historical disappearance when supporting event exists", () => {
    const codes = issues(review({
      state: "NO_LONGER_DETECTED",
      diagnostic: null,
      historicalOnly: true,
    }));
    expect(codes).not.toContain("NO_LONGER_DETECTED_WITH_DIAGNOSTIC");
    expect(codes).not.toContain("HISTORICAL_WITHOUT_REVIEW");
  });
  it.each(["ACKNOWLEDGED", "DISMISSED"] as const)(
    "warns when %s lacks a review rationale", state => {
      expect(issues(review({ state, reviewRationale: null })))
        .toContain("CLOSED_REVIEW_WITHOUT_RATIONALE");
    },
  );
  it("rejects review events that occur after the capture time", () => {
    expect(issues(review({ reviewedAt: "2026-10-31T15:00:00.000Z" })))
      .toContain("REVIEW_AFTER_CAPTURE");
  });
  it("allows bounded clock skew of five minutes", () => {
    expect(issues(review({ reviewedAt: "2026-10-31T14:04:00.000Z" })))
      .not.toContain("REVIEW_AFTER_CAPTURE");
  });
  it("rejects invalid review times instead of silently converting them", () => {
    expect(issues(review({ reviewedAt: "not-a-date" }))).toContain("FUTURE_REVIEW_TIME");
  });
  it("counts affected cases once when multiple problems share the same case", () => {
    const result = inspectCaptureQuality(snapshot([{
      ...base,
      completeCoverage: false,
      state: "INVESTIGATING",
    }]));
    expect(result.affectedCases).toBe(1);
    expect(result.blockers).toBeGreaterThan(0);
  });
  it("does not fabricate cases when no diagnostics are present", () => {
    const result = inspectCaptureQuality(snapshot([]));
    expect(result.caseCount).toBe(0);
    expect(result.information).toBe(1);
    expect(result.affectedCases).toBe(0);
    expect(result.byCode.CAPTURE_WITHOUT_CASES).toBe(1);
  });
  it("caps responses but continues counting suppressed issues", () => {
    const result = inspectCaptureQuality(snapshot([
      { ...base, completeCoverage: false, state: "INVESTIGATING" },
    ]), { maximumIssues: 1 });
    expect(result.issues).toHaveLength(1);
    expect(result.blockers + result.warnings).toBeGreaterThan(1);
    expect(result.limitations.join(" ")).toContain("omitted");
  });
  it.each([
    { maximumIssues: 0 },
    { maximumIssues: 10001 },
    { futureToleranceMs: -1 },
    { futureToleranceMs: 3600001 },
  ])("rejects an unsafe inspection configuration %j", options => {
    expect(() => inspectCaptureQuality(snapshot(), options)).toThrow();
  });
  it("does not read external organizations or perform writes", () => {
    const result = inspectCaptureQuality(snapshot());
    expect(result.organizationId).toBe("org-123");
    expect(result.issues).toEqual([]);
  });
});
