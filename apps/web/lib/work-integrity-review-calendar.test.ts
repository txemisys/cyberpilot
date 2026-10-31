import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot } from "./work-integrity-snapshots";
import {
  DEFAULT_REVIEW_CADENCES, validateReviewCalendarPolicy, createReviewCalendar,
  reviewCalendarStatus, assessReviewCalendar, compareReviewCalendars,
  reviewCalendarCsv, reviewCalendarJson,
} from "./work-integrity-review-calendar";
const row = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 1, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Inspect",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const start = "2026-10-31T10:00:00.000Z";
const capture = (rows: CaseRow[], complete = true, capturedAt = start) =>
  parseCaseSnapshot({ organizationId: "org-a", source: "offline",
    capturedAt, complete, cases: rows });
const urgent = row("urgent", { severity: "critical" });
const normal = row("normal");
const historical = row("historical", { historicalOnly: true });
const reviewed = row("reviewed", { reviewEventId: "event-1" });
const incomplete = row("incomplete", { completeCoverage: false });
const policy = {
  cadences: DEFAULT_REVIEW_CADENCES,
  maxItems: 1000, excludeHistorical: true, excludeReviewed: false,
  requireCompleteSnapshot: true,
};
describe("review calendar policy", () => {
  it("accepts five cadences", () => expect(validateReviewCalendarPolicy(policy).cadences).toHaveLength(5));
  it("rejects missing cadences", () => expect(() => validateReviewCalendarPolicy({
    ...policy, cadences: DEFAULT_REVIEW_CADENCES.slice(1),
  })).toThrow());
  it("rejects duplicate priorities", () => expect(() => validateReviewCalendarPolicy({
    ...policy, cadences: DEFAULT_REVIEW_CADENCES.map((item, index) =>
      index === 0 ? { ...item, priority: "P1" as const } : item),
  })).toThrow());
  it("rejects negative deadlines", () => expect(() => validateReviewCalendarPolicy({
    ...policy, cadences: DEFAULT_REVIEW_CADENCES.map((item, index) =>
      index === 0 ? { ...item, dueWithinHours: -1 } : item),
  })).toThrow());
  it("rejects escalation before due", () => expect(() => validateReviewCalendarPolicy({
    ...policy, cadences: DEFAULT_REVIEW_CADENCES.map((item, index) =>
      index === 0 ? { ...item, escalationAfterHours: 1 } : item),
  })).toThrow());
  it("rejects zero item bound", () => expect(() => validateReviewCalendarPolicy({
    ...policy, maxItems: 0,
  })).toThrow());
  it("rejects noninteger item bound", () => expect(() => validateReviewCalendarPolicy({
    ...policy, maxItems: 1.5,
  })).toThrow());
  it("rejects invalid flags", () => expect(() => validateReviewCalendarPolicy({
    ...policy, excludeHistorical: "yes" as never,
  })).toThrow());
});
describe("calendar generation", () => {
  const source = capture([urgent, normal, historical, reviewed, incomplete]);
  const calendar = createReviewCalendar(source, policy);
  it("records organization", () => expect(calendar.organizationId).toBe("org-a"));
  it("omits historical cases", () => expect(calendar.entries).toHaveLength(4));
  it("counts omitted cases", () => expect(calendar.omitted).toBe(1));
  it("prioritizes critical cases", () => expect(calendar.entries[0]?.priority).toBe("P0"));
  it("calculates P0 due time", () => expect(calendar.entries[0]?.dueAt).toBe("2026-10-31T14:00:00.000Z"));
  it("calculates P0 escalation", () => expect(calendar.entries[0]?.escalationAt).toBe("2026-10-31T18:00:00.000Z"));
  it("excludes reviewed when requested", () => expect(createReviewCalendar(source, {
    ...policy, excludeReviewed: true,
  }).entries).toHaveLength(3));
  it("rejects partial snapshot under strict policy", () => expect(() => createReviewCalendar(
    capture([normal], false), policy,
  )).toThrow());
  it("allows partial snapshot with explicit policy", () => expect(createReviewCalendar(
    capture([normal], false), { ...policy, requireCompleteSnapshot: false },
  ).complete).toBe(false));
  it("rejects excessive items", () => expect(() => createReviewCalendar(source, {
    ...policy, maxItems: 1,
  })).toThrow());
  it("rejects noncanonical timestamp", () => expect(() => createReviewCalendar(
    { ...source, capturedAt: "2026-10-31T10:00:00Z" }, policy,
  )).toThrow());
  it("retains task revision", () => expect(calendar.entries[0]?.revision).toBe(1));
  it("does not claim notifications", () => expect(calendar.warnings.some(w => w.includes("does not send"))).toBe(true));
  it("serializes JSON", () => expect(JSON.parse(reviewCalendarJson(calendar)).version).toBe(1));
  it("serializes CSV", () => expect(reviewCalendarCsv(calendar)).toContain("\r\n"));
  it("neutralizes formula cells", () => {
    const formula = row("=HYPERLINK");
    expect(reviewCalendarCsv(createReviewCalendar(capture([formula]), policy))).toContain("'=HYPERLINK");
  });
});
describe("calendar status assessment", () => {
  const calendar = createReviewCalendar(capture([urgent]), policy);
  const item = calendar.entries[0]!;
  it("reports upcoming", () => expect(reviewCalendarStatus(item, "2026-10-31T13:59:59.000Z")).toBe("UPCOMING"));
  it("reports due at exact deadline", () => expect(reviewCalendarStatus(item, "2026-10-31T14:00:00.000Z")).toBe("DUE"));
  it("reports escalated at exact deadline", () => expect(reviewCalendarStatus(item, "2026-10-31T18:00:00.000Z")).toBe("ESCALATED"));
  it("reports unknown for incomplete coverage", () => expect(reviewCalendarStatus({
    ...item, coverageComplete: false,
  }, "2026-10-31T19:00:00.000Z")).toBe("UNKNOWN"));
  it("rejects invalid assessment time", () => expect(() => reviewCalendarStatus(item, "invalid")).toThrow());
  it("rejects reversed escalation", () => expect(() => reviewCalendarStatus({
    ...item, escalationAt: "2026-10-31T12:00:00.000Z",
  }, "2026-10-31T13:00:00.000Z")).toThrow());
  it("aggregates upcoming", () => expect(assessReviewCalendar(calendar,
    "2026-10-31T11:00:00.000Z").byStatus.UPCOMING).toBe(1));
  it("aggregates escalated", () => expect(assessReviewCalendar(calendar,
    "2026-10-31T19:00:00.000Z").byStatus.ESCALATED).toBe(1));
  it("marks partial captures unknown", () => {
    const partial = createReviewCalendar(capture([urgent], false), {
      ...policy, requireCompleteSnapshot: false,
    });
    expect(assessReviewCalendar(partial, "2026-10-31T19:00:00.000Z").byStatus.UNKNOWN).toBe(1);
  });
});
describe("calendar comparison", () => {
  const old = createReviewCalendar(capture([urgent]), policy);
  const next = createReviewCalendar(capture([urgent, normal], true,
    "2026-10-31T11:00:00.000Z"), policy);
  it("detects new cases", () => expect(compareReviewCalendars(old, next).some(change =>
    change.kind === "ADDED")).toBe(true));
  it("detects rescheduling", () => expect(compareReviewCalendars(old, next).some(change =>
    change.kind === "RESCHEDULED")).toBe(true));
  it("detects removed cases", () => expect(compareReviewCalendars(next, old).some(change =>
    change.kind === "REMOVED")).toBe(true));
  it("detects unchanged calendar", () => expect(compareReviewCalendars(old, old)[0]?.kind).toBe("UNCHANGED"));
  it("rejects cross-tenant comparisons", () => expect(() => compareReviewCalendars(old, {
    ...next, organizationId: "other",
  })).toThrow());
  it("marks missing case uncertain when capture incomplete", () => expect(compareReviewCalendars(
    old, { ...next, complete: false, entries: [] },
  )[0]?.kind).toBe("UNCERTAIN"));
});
