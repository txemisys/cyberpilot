import { describe, expect, it } from "vitest";
import {
  CASE_STATES, caseKey, caseSummary, combineCasePage, filterCaseRows,
  latestReviewByCase, orderCaseRows, parseCaseFilters, priorityOfCase,
  stateFromReview, type CasePageSource, type CaseRow,
} from "./work-integrity-cases";
import type { TriageEvent } from "./work-integrity-triage";
import type { IntegrityFinding } from "./work-integrity";
const timestamp = new Date("2026-10-31T12:00:00.000Z");
const finding = (
  workItemId: string,
  code: IntegrityFinding["code"] = "FINDING_MISMATCH",
  resourceId = "finding_001",
  severity: IntegrityFinding["severity"] = "critical",
): IntegrityFinding => ({
  workItemId, resourceId, code, severity,
  message: "Stored relationship requires investigation.",
  recommendation: "Review the stored relationship without guessing control verification.",
});
const review = (
  workItemId: string, overrides: Partial<TriageEvent> = {},
): TriageEvent => ({
  id: "audit_00001", organizationId: "org_00001",
  workItemId, code: "FINDING_MISMATCH", resourceId: "finding_001",
  decision: "INVESTIGATE", revision: 3,
  occurredAt: timestamp, actorUserId: "user_00001",
  rationale: "Investigate inconsistent records.",
  reference: "CASE-001", previousEventId: null,
  ...overrides,
});
const source = (): CasePageSource => ({
  checked: 3,
  nextCursor: "2026-10-30T12:00:00.000Z.work_00003",
  limitations: ["Historical review is not a verified security outcome."],
  items: [
    { workItemId: "work_00001", status: "BLOCKED", revision: 3,
      complete: true, findings: [finding("work_00001")] },
    { workItemId: "work_00002", status: "TODO", revision: 2,
      complete: false, findings: [finding("work_00002", "ASSIGNEE_NOT_MEMBER", "user_00002", "attention")] },
    { workItemId: "work_00003", status: "DONE", revision: 1,
      complete: true, findings: [] },
  ],
});
function row(overrides: Partial<CaseRow> = {}): CaseRow {
  return {
    key: caseKey("work_00001", "FINDING_MISMATCH", "finding_001"),
    workItemId: "work_00001", taskStatus: "BLOCKED", taskRevision: 3,
    resourceId: "finding_001", code: "FINDING_MISMATCH", severity: "critical",
    diagnostic: "Anomaly", recommendation: "Investigate",
    state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
    reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
    reviewReference: null, completeCoverage: true, historicalOnly: false,
    ...overrides,
  };
}
describe("integrity case filter validation", () => {
  it("defaults to bounded work pages", () => {
    expect(parseCaseFilters({})).toEqual({
      state: "ALL", severity: "ALL", search: "", limit: 25, cursor: null,
      includeInfo: false, includeHistorical: false,
    });
  });
  it.each(CASE_STATES)("accepts case state %s", state => {
    expect(parseCaseFilters({ state }).state).toBe(state);
  });
  it.each(["critical", "attention", "info", "ALL"])(
    "accepts known severity %s", severity => {
      expect(parseCaseFilters({ severity }).severity).toBe(severity);
    },
  );
  it.each([10, 25, 50, 100])("accepts page size %i", limit => {
    expect(parseCaseFilters({ limit }).limit).toBe(limit);
  });
  it.each([0, 1, 20, 101, -5, 2.5, "abc", Infinity])(
    "rejects unsupported page size %s", limit => {
      expect(() => parseCaseFilters({ limit })).toThrow();
    },
  );
  it.each(["VERIFIED", "COMPLETED", 2, null])(
    "rejects unsupported case status %s", state => {
      expect(() => parseCaseFilters({ state })).toThrow();
    },
  );
  it.each(["high", "unknown", 42, null])(
    "rejects unsupported severity %s", severity => {
      expect(() => parseCaseFilters({ severity })).toThrow();
    },
  );
  it.each(["1", "yes", true, null])(
    "rejects ambiguous includeHistorical %s", includeHistorical => {
      expect(() => parseCaseFilters({ includeHistorical })).toThrow();
    },
  );
  it.each(["1", "yes", true, null])(
    "rejects ambiguous includeInfo %s", includeInfo => {
      expect(() => parseCaseFilters({ includeInfo })).toThrow();
    },
  );
  it("trims and normalizes search to lower case", () => {
    expect(parseCaseFilters({ search: "  ANOMALY  " }).search).toBe("anomaly");
  });
  it("preserves a bounded cursor unchanged", () => {
    expect(parseCaseFilters({ cursor: "2026-10-30T12:00:00.000Z.work_00003" }).cursor)
      .toBe("2026-10-30T12:00:00.000Z.work_00003");
  });
  it("does not accept overlong search", () => {
    expect(() => parseCaseFilters({ search: "a".repeat(121) })).toThrow();
  });
  it("does not accept control characters in search", () => {
    expect(() => parseCaseFilters({ search: "a\u0000b" })).toThrow();
  });
  it("treats empty cursor as first page", () => {
    expect(parseCaseFilters({ cursor: "" }).cursor).toBeNull();
  });
  it("cannot accept overlong cursor", () => {
    expect(() => parseCaseFilters({ cursor: "a".repeat(301) })).toThrow();
  });
});
describe("review decision state machine projection", () => {
  it("distinguishes unreviewed findings", () => {
    expect(stateFromReview(null, null, 3, true)).toBe("UNREVIEWED");
  });
  it("marks old review revisions stale before other classification", () => {
    expect(stateFromReview("DISMISS", 2, 3, true)).toBe("STALE");
    expect(stateFromReview("ACKNOWLEDGE", 2, 3, false)).toBe("STALE");
  });
  it.each([
    ["INVESTIGATE", "INVESTIGATING"],
    ["ACKNOWLEDGE", "ACKNOWLEDGED"],
    ["DISMISS", "DISMISSED"],
    ["REOPEN", "REOPENED"],
  ] as const)("maps persisted decision %s to case state %s", (decision, expected) => {
    expect(stateFromReview(decision, 3, 3, true)).toBe(expected);
  });
  it("treats fully covered no-longer-detected diagnostic as historical", () => {
    expect(stateFromReview("DISMISS", 3, 3, false)).toBe("NO_LONGER_DETECTED");
  });
  it("does not infer resolution merely from an absent previous decision", () => {
    expect(stateFromReview(null, null, 3, false)).toBe("NO_LONGER_DETECTED");
  });
});
describe("scoped case joins and history", () => {
  it("does not invent a review when the audit log is empty", () => {
    const cases = combineCasePage(source(), []);
    expect(cases).toHaveLength(2);
    expect(cases.every(item => item.state === "UNREVIEWED")).toBe(true);
  });
  it("joins a decision by work item, code and resource", () => {
    const cases = combineCasePage(source(), [review("work_00001")]);
    expect(cases[0]?.state).toBe("INVESTIGATING");
    expect(cases[1]?.state).toBe("UNREVIEWED");
  });
  it("does not join a decision for a different work item", () => {
    const cases = combineCasePage(source(), [review("work_00099")]);
    expect(cases[0]?.reviewEventId).toBeNull();
  });
  it("does not join a decision for another diagnostic code", () => {
    const cases = combineCasePage(source(), [
      review("work_00001", { code: "ASSIGNEE_NOT_MEMBER" }),
    ]);
    expect(cases[0]?.state).toBe("UNREVIEWED");
  });
  it("does not join a decision for another resource", () => {
    const cases = combineCasePage(source(), [
      review("work_00001", { resourceId: "finding_002" }),
    ]);
    expect(cases[0]?.state).toBe("UNREVIEWED");
  });
  it("uses the latest audit event when reviews were repeated", () => {
    const events = [
      review("work_00001"),
      review("work_00001", {
        id: "audit_00002", decision: "ACKNOWLEDGE",
        occurredAt: new Date("2026-11-01T12:00:00.000Z"),
      }),
    ];
    expect(combineCasePage(source(), events)[0]?.state).toBe("ACKNOWLEDGED");
  });
  it("marks earlier revision reviews stale", () => {
    const cases = combineCasePage(source(), [review("work_00001", { revision: 1 })]);
    expect(cases[0]?.state).toBe("STALE");
  });
  it("does not show historical-only review unless requested", () => {
    expect(combineCasePage(source(), [
      review("work_00003", { revision: 1 }),
    ])).toHaveLength(2);
  });
  it("shows a historical-only reviewed case when fully covered", () => {
    const cases = combineCasePage(source(), [
      review("work_00003", { revision: 1 }),
    ], true);
    expect(cases).toHaveLength(3);
    expect(cases[2]?.historicalOnly).toBe(true);
    expect(cases[2]?.state).toBe("NO_LONGER_DETECTED");
    expect(cases[2]?.severity).toBeNull();
  });
  it("withholds historical-only review when linked data coverage is incomplete", () => {
    const cases = combineCasePage(source(), [
      review("work_00002", {
        code: "FINDING_MISMATCH", resourceId: "finding_002", revision: 2,
      }),
    ], true);
    expect(cases).toHaveLength(2);
  });
  it("deduplicates repeated identical diagnostic signals", () => {
    const input = source();
    input.items[0]!.findings.push(finding("work_00001"));
    expect(combineCasePage(input, [])).toHaveLength(2);
  });
  it("does not mutate underlying diagnostic or audit records", () => {
    const input = source();
    const events = [review("work_00001")];
    const before = JSON.stringify({ input, events });
    combineCasePage(input, events, true);
    expect(JSON.stringify({ input, events })).toBe(before);
  });
  it("includes human rationale and audit reference", () => {
    const cases = combineCasePage(source(), [review("work_00001")]);
    expect(cases[0]?.reviewRationale).toContain("Investigate");
    expect(cases[0]?.reviewReference).toBe("CASE-001");
    expect(cases[0]?.reviewerUserId).toBe("user_00001");
  });
  it("preserves exact diagnostic text", () => {
    const cases = combineCasePage(source(), []);
    expect(cases[0]?.diagnostic).toBe("Stored relationship requires investigation.");
  });
  it("avoids collision with delimiter-containing identifiers", () => {
    expect(caseKey("a_b", "FINDING_MISMATCH", "c.d"))
      .not.toBe(caseKey("a", "FINDING_MISMATCH", "b_c.d"));
  });
  it("deduplicates latest reviews by chronological order", () => {
    const mapped = latestReviewByCase([
      review("work_00001", { id: "audit_00002",
        occurredAt: new Date("2026-11-01T12:00:00.000Z") }),
      review("work_00001"),
    ]);
    expect([...mapped.values()][0]?.id).toBe("audit_00002");
  });
  it("breaks equal timestamp ties by audit event identifier", () => {
    const mapped = latestReviewByCase([
      review("work_00001", { id: "audit_00001" }),
      review("work_00001", { id: "audit_00002" }),
    ]);
    expect([...mapped.values()][0]?.id).toBe("audit_00002");
  });
});
describe("case dashboard ordering and summarization", () => {
  it("returns the zero summary for an empty page", () => {
    expect(caseSummary([])).toMatchObject({
      totalOnPage: 0, critical: 0, attention: 0, partialCoverage: 0,
      unreviewed: 0, reviewed: 0,
    });
  });
  it("counts each diagnostic rather than incorrectly counting work items", () => {
    const result = caseSummary([
      row(), row({ code: "ASSIGNEE_NOT_MEMBER", severity: "attention" }),
    ]);
    expect(result.totalOnPage).toBe(2);
    expect(result.critical).toBe(1);
    expect(result.attention).toBe(1);
  });
  it("counts review states independently", () => {
    const states = CASE_STATES.map(state => row({ state }));
    const summary = caseSummary(states);
    expect(summary.unreviewed).toBe(1);
    expect(summary.investigating).toBe(1);
    expect(summary.stale).toBe(1);
    expect(summary.noLongerDetected).toBe(1);
  });
  it("counts partial coverage explicitly", () => {
    expect(caseSummary([row({ completeCoverage: false })]).partialCoverage).toBe(1);
  });
  it("counts recorded human review separately from current status", () => {
    expect(caseSummary([row({
      reviewEventId: "audit_00001", state: "STALE",
    })]).reviewed).toBe(1);
  });
  it("prioritizes stale and critical unreviewed findings", () => {
    expect(priorityOfCase(row({ state: "STALE" })))
      .toBeLessThan(priorityOfCase(row()));
  });
  it("orders without mutating the original array", () => {
    const values = [
      row({ workItemId: "work_00002", state: "ACKNOWLEDGED" }),
      row({ workItemId: "work_00001", state: "STALE" }),
    ];
    const before = [...values];
    const sorted = orderCaseRows(values);
    expect(sorted[0]?.state).toBe("STALE");
    expect(values).toEqual(before);
  });
  it("filters by exact state", () => {
    const rows = [row(), row({ state: "STALE" })];
    expect(filterCaseRows(rows, parseCaseFilters({ state: "STALE" }))).toHaveLength(1);
  });
  it("filters case search without case sensitivity", () => {
    expect(filterCaseRows([row()], parseCaseFilters({ search: "FINDING_MISMATCH" }))).toHaveLength(1);
  });
  it("filters by diagnostic severity", () => {
    const rows = [row(), row({ severity: "attention" })];
    expect(filterCaseRows(rows, parseCaseFilters({ severity: "attention" }))).toHaveLength(1);
  });
  it("excludes info by default", () => {
    const rows = [row({ severity: "info" })];
    expect(filterCaseRows(rows, parseCaseFilters({}))).toHaveLength(0);
    expect(filterCaseRows(rows, parseCaseFilters({ includeInfo: "true" }))).toHaveLength(1);
  });
  it("treats historical-only rows as separate from currently detected diagnostics", () => {
    const result = caseSummary([row({ historicalOnly: true, severity: null })]);
    expect(result.historicalOnly).toBe(1);
    expect(result.critical).toBe(0);
  });
});
