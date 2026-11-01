import { describe, expect, it } from "vitest";
import type { LedgerEntry, LedgerPage } from "./work-integrity-audit-ledger";
import {
  reconstructDecisionPaths, decisionPathCsv,
} from "./work-integrity-ledger-decision-path";
const row = (id: string, previous: string | null, extra: Partial<LedgerEntry> = {}): LedgerEntry => ({
  eventId: id, organizationId: "tenant-a",
  occurredAt: id === "a" ? "2026-10-01T10:00:00.000Z" :
    "2026-10-02T10:00:00.000Z",
  actorUserId: "reviewer-1", workItemId: "work-123",
  resourceId: "work-123", code: "DONE_WITHOUT_COMPLETION",
  revision: 2, decision: id === "a" ? "INVESTIGATE" : "ACKNOWLEDGE",
  rationale: "Investigated source evidence", reference: null,
  predecessorEventId: previous,
  predecessorInPage: previous !== null,
  predecessorChronologicallyPrior: previous === null ? null : true,
  workTitle: "Evidence review", workStatus: "DONE",
  currentWorkRevision: 2, reviewedRevisionIsCurrent: true,
  source: "AUDIT_EVENT", ...extra,
});
const page = (rows: LedgerEntry[]): LedgerPage => ({
  organizationId: "tenant-a", generatedAt: "2026-10-04T00:00:00.000Z",
  filters: {
    limit: 25, cursor: null, workItemId: null, actorUserId: null,
    decision: null, includeMalformed: false,
  },
  entries: rows, malformed: [], fetched: rows.length, matched: rows.length,
  nextCursor: null, coverage: "BOUNDED_RAW_AUDIT_PAGE", limitations: [],
});
const issues = (...rows: LedgerEntry[]) =>
  reconstructDecisionPaths(page(rows)).paths.flatMap(path =>
    path.issues.map(issue => issue.code));
describe("stored human-review decision path reconstruction", () => {
  it("retains a valid bounded review transition", () => {
    const result = reconstructDecisionPaths(page([
      row("a", null), row("b", "a"),
    ]));
    expect(result.errors).toBe(0);
    expect(result.totalPaths).toBe(1);
    expect(result.paths[0]?.linkedPredecessorsOnPage).toBe(1);
    expect(result.paths[0]?.hasAuthoritativeCompleteHistory).toBe(false);
  });
  it("rejects cross-tenant event collections", () => {
    expect(() => reconstructDecisionPaths(page([
      row("a", null, { organizationId: "foreign" }),
    ]))).toThrow(/cross-organization/);
  });
  it("rejects duplicate event identifiers", () => {
    expect(() => reconstructDecisionPaths(page([
      row("a", null), row("a", null),
    ]))).toThrow(/Repeated event/);
  });
  it("detects reopening without a prior disposition", () => {
    expect(issues(
      row("a", null),
      row("b", "a", { decision: "REOPEN" }),
    )).toContain("REOPEN_WITHOUT_DISPOSITION");
  });
  it("rejects consecutive reopened reviews", () => {
    expect(issues(
      row("a", null, { decision: "REOPEN" }),
      row("b", "a", { decision: "REOPEN" }),
    )).toContain("ILLEGAL_REPEAT_REOPEN");
  });
  it("does not invent a missing predecessor", () => {
    const result = reconstructDecisionPaths(page([
      row("b", "earlier"),
    ]));
    expect(result.unknowns).toBe(1);
    expect(result.paths[0]?.predecessorLinksOutsidePage).toBe(1);
  });
  it("detects predecessor crossing case identities", () => {
    expect(issues(
      row("a", null),
      row("b", "a", { resourceId: "work-other" }),
    )).toContain("CROSS_CASE_PREDECESSOR");
  });
  it("detects decreasing reviewed work revision", () => {
    expect(issues(
      row("a", null, { revision: 3 }),
      row("b", "a", { revision: 2 }),
    )).toContain("DECREASING_WORK_REVISION");
  });
  it("detects a timestamp contradiction", () => {
    expect(issues(
      row("a", null, { occurredAt: "2026-10-03T10:00:00.000Z" }),
      row("b", "a"),
    )).toContain("REVIEW_EVENT_AFTER_SUCCESSOR");
  });
  it("detects an optimistic-locking fork", () => {
    expect(issues(
      row("a", null), row("b", "a"),
      row("c", "a", { decision: "DISMISS" }),
    )).toContain("MULTIPLE_SUCCESSORS");
  });
  it("detects cycles without infinite traversal", () => {
    expect(issues(row("a", "b"), row("b", "a")))
      .toContain("CYCLE_IN_SELECTED_PAGE");
  });
  it("checks the first explicit reopen root", () => {
    expect(issues(row("a", null, { decision: "REOPEN" })))
      .toContain("ILLEGAL_FIRST_REOPEN");
  });
  it("detects a missing reopen after disposition", () => {
    expect(issues(
      row("a", null, { decision: "ACKNOWLEDGE" }),
      row("b", "a", { decision: "INVESTIGATE" }),
    )).toContain("DECISION_AFTER_DISPOSITION_WITHOUT_REOPEN");
  });
  it("accepts a reopened disposition followed by investigation", () => {
    const result = reconstructDecisionPaths(page([
      row("a", null, { decision: "ACKNOWLEDGE" }),
      row("b", "a", { decision: "REOPEN" }),
      row("c", "b", { decision: "INVESTIGATE" }),
    ]));
    expect(result.errors).toBe(0);
    expect(result.paths[0]?.reopenedOnPage).toBe(1);
  });
  it("exports investigative paths in CSV without overwriting source decisions", () => {
    const rows = [row("a", null), row("b", "a", { decision: "REOPEN" })];
    const before = JSON.stringify(rows);
    const csv = decisionPathCsv(reconstructDecisionPaths(page(rows)));
    expect(csv).toContain("REOPEN_WITHOUT_DISPOSITION");
    expect(csv).toContain("predecessorEventId");
    expect(JSON.stringify(rows)).toBe(before);
  });
});
