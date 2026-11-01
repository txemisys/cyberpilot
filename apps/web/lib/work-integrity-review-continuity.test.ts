import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { analyzeReviewContinuity, reviewContinuityCsv } from "./work-integrity-review-continuity";
import { planContinuityActions, continuityActionsCsv } from "./work-integrity-continuity-actions";

const a: CaseRow = {
  key: JSON.stringify(["work-123", "DONE_WITHOUT_COMPLETION", "work-123"]),
  workItemId: "work-123", code: "DONE_WITHOUT_COMPLETION", resourceId: "work-123",
  taskStatus: "DONE", taskRevision: 2, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "INVESTIGATING", reviewEventId: "audit-1",
  reviewedAt: "2026-10-01T11:00:00.000Z", reviewedRevision: 2,
  reviewerUserId: "user-123", reviewRationale: "Investigating",
  reviewReference: "case-ref", completeCoverage: true, historicalOnly: false,
};
const capture = (
  day: number, cases: CaseRow[] = [a], complete = true,
  organizationId = "org-123", source = "same-scope",
) => ({
  organizationId, source, complete,
  capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  cases,
});
const analyze = (first: CaseRow, second: CaseRow) =>
  analyzeReviewContinuity([capture(2, [first]), capture(3, [second])]);
const codes = (first: CaseRow, second: CaseRow) =>
  analyze(first, second).transitions[0]!.findings.map(f => f.kind);

describe("review continuity across real capture metadata", () => {
  it("records no anomalies for an unchanged reviewed case", () => {
    const report = analyze(a, a);
    expect(report.transitions[0]?.findings).toEqual([]);
    expect(report.caseIdentities).toBe(1);
    expect(report.eventIdentities).toBe(1);
  });
  it("rejects different authenticated organizations", () => {
    expect(() => analyzeReviewContinuity([
      capture(2), capture(3, [a], true, "foreign"),
    ])).toThrow(/Cross-organization/);
  });
  it("rejects changing capture filters or provenance scopes", () => {
    expect(() => analyzeReviewContinuity([
      capture(2), capture(3, [a], true, "org-123", "other"),
    ])).toThrow(/scopes differ/);
  });
  it("rejects non-monotonic capture times", () => {
    expect(() => analyzeReviewContinuity([capture(3), capture(2)])).toThrow();
    expect(() => analyzeReviewContinuity([capture(2), capture(2)])).toThrow();
  });
  it("rejects insufficient capture history", () => {
    expect(() => analyzeReviewContinuity([capture(2)])).toThrow();
  });
  it("detects a work revision moving backward", () => {
    expect(codes(a, { ...a, taskRevision: 1 })).toContain("WORK_REVISION_REWOUND");
  });
  it("detects reviewed revision rewind", () => {
    expect(codes(a, { ...a, reviewedRevision: 1 }))
      .toContain("REVIEW_REVISION_REWOUND");
  });
  it("detects review revision ahead of captured work state", () => {
    expect(codes(a, { ...a, reviewedRevision: 3 }))
      .toContain("REVIEW_REVISION_AHEAD");
  });
  it("does not call outdated reviews current", () => {
    expect(codes(a, { ...a, taskRevision: 3, state: "STALE" }))
      .toContain("REVIEW_STALE");
  });
  it("detects decisions changing without a new audited event", () => {
    expect(codes(a, { ...a, state: "ACKNOWLEDGED" }))
      .toContain("DECISION_CHANGED_WITHOUT_EVENT");
  });
  it("detects changed audit content under the same event identity", () => {
    expect(codes(a, { ...a, reviewRationale: "Different" }))
      .toContain("REVIEW_EVENT_CONTENT_CHANGED");
  });
  it("flags missing event when the case remains present", () => {
    expect(codes(a, { ...a, reviewEventId: null, reviewedRevision: null }))
      .toContain("REVIEW_EVENT_DISAPPEARED");
  });
  it("flags an absent review after task revision", () => {
    expect(codes(a, { ...a, taskRevision: 3, reviewEventId: null }))
      .toContain("REVIEW_ABSENT_ON_NEW_REVISION");
  });
  it("detects future review timestamps", () => {
    expect(codes(a, { ...a, reviewedAt: "2026-10-04T12:00:00.000Z" }))
      .toContain("REVIEW_TIME_AFTER_CAPTURE");
  });
  it("detects timestamps that move backward", () => {
    expect(codes(a, { ...a, reviewedAt: "2026-09-30T11:00:00.000Z" }))
      .toContain("REVIEW_TIME_REWOUND");
  });
  it("flags a review without a current actor", () => {
    expect(codes(a, { ...a, reviewerUserId: null }))
      .toContain("REVIEW_UNATTRIBUTED");
  });
  it("flags a review without rationale", () => {
    expect(codes(a, { ...a, reviewRationale: null }))
      .toContain("REVIEW_WITHOUT_RATIONALE");
  });
  it("reports incomplete source coverage rather than guessing disappearance", () => {
    const report = analyzeReviewContinuity([
      capture(2, [a]), capture(3, [], false),
    ]);
    expect(report.byKind.SOURCE_SCOPE_INCOMPLETE).toBe(1);
    expect(report.byKind.REVIEW_EVENT_DISAPPEARED).toBeUndefined();
  });
  it("reports event identity reused under different cases", () => {
    const b = {
      ...a, workItemId: "work-456", resourceId: "work-456",
      key: JSON.stringify(["work-456", a.code, "work-456"]),
    };
    const report = analyzeReviewContinuity([
      capture(2, [a]), capture(3, [b]),
    ]);
    expect(report.byKind.REVIEW_EVENT_REUSED_FOR_DIFFERENT_CASE).toBe(1);
  });
  it("refuses one event identity repeated across different current cases", () => {
    const b = {
      ...a, workItemId: "work-456", resourceId: "work-456",
      key: JSON.stringify(["work-456", a.code, "work-456"]),
    };
    expect(() => analyzeReviewContinuity([
      capture(2, [a]), capture(3, [a, b]),
    ])).toThrow(/One review event/);
  });
  it("exports deterministic, neutralized CSV", () => {
    const row = { ...a, reviewerUserId: null };
    const csv = reviewContinuityCsv(analyze(a, row));
    expect(csv).toContain("REVIEW_UNATTRIBUTED");
    expect(csv).toContain("eventId");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
describe("deduplicated human continuity handoffs", () => {
  it("does not fabricate actions for a consistent review history", () => {
    const plan = planContinuityActions(analyze(a, a));
    expect(plan.actions).toEqual([]);
    expect(plan.totalActionCandidates).toBe(0);
  });
  it("maps audit source integrity anomalies to urgent investigation", () => {
    const plan = planContinuityActions(analyze(a, {
      ...a, reviewRationale: "Changed rationale",
    }));
    expect(plan.actions[0]?.priority).toBe("P0");
    expect(plan.actions[0]?.requiresSourceAccess).toBe(true);
    expect(plan.actions[0]?.cannotCloseAutomatically).toBe(true);
  });
  it("deduplicates successive observations of the same failure", () => {
    const second = { ...a, reviewerUserId: null };
    const report = analyzeReviewContinuity([
      capture(2, [a]), capture(3, [second]), capture(4, [second]),
    ]);
    const plan = planContinuityActions(report);
    const entry = plan.actions.find(action => action.type === "CHECK_EVENT_ATTRIBUTION");
    expect(entry?.occurrences).toBe(2);
  });
  it("retains diagnostic counts even when export is capped", () => {
    const report = analyze(a, {
      ...a, taskRevision: 1, reviewedRevision: 3,
      reviewerUserId: null, reviewRationale: null,
    });
    const all = planContinuityActions(report);
    const limited = planContinuityActions(report, { limit: 1 });
    expect(all.totalActionCandidates).toBeGreaterThan(1);
    expect(limited.actions).toHaveLength(1);
    expect(limited.truncated).toBe(true);
    expect(limited.totalActionCandidates).toBe(all.totalActionCandidates);
  });
  it("rejects invalid action response limits", () => {
    const report = analyze(a, a);
    expect(() => planContinuityActions(report, { limit: 0 })).toThrow();
    expect(() => planContinuityActions(report, { limit: 1001 })).toThrow();
    expect(() => planContinuityActions(report, { limit: 1.2 })).toThrow();
  });
  it("escapes spreadsheet formulas in a bounded action export", () => {
    const row = { ...a, reviewRationale: "=SUM(A1:A2)" };
    const report = analyze(a, row);
    const csv = continuityActionsCsv(planContinuityActions(report));
    expect(csv).toContain("RECONCILE_AUDIT_SOURCE");
    expect(csv).toContain("cannotCloseAutomatically");
  });
});
