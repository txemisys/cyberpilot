import { describe, expect, it } from "vitest";
import type { LedgerEntry, LedgerPage } from "./work-integrity-audit-ledger";
import { inspectLedgerInsights, ledgerInsightsCsv } from "./work-integrity-ledger-insights";
const row = (id: string, extra: Partial<LedgerEntry> = {}): LedgerEntry => ({
  eventId: id, organizationId: "org-a",
  occurredAt: id === "a" ? "2026-10-01T10:00:00.000Z" :
    "2026-10-02T10:00:00.000Z",
  actorUserId: "reviewer-1", workItemId: "work-123",
  code: "DONE_WITHOUT_COMPLETION", resourceId: "work-123",
  revision: 2, decision: id === "a" ? "INVESTIGATE" : "ACKNOWLEDGE",
  rationale: "Reviewed the work", reference: null,
  predecessorEventId: id === "a" ? null : "a",
  predecessorInPage: id !== "a",
  predecessorChronologicallyPrior: id === "a" ? null : true,
  workTitle: "Review item", workStatus: "DONE",
  currentWorkRevision: 2, reviewedRevisionIsCurrent: true,
  source: "AUDIT_EVENT", ...extra,
});
const page = (entries: LedgerEntry[]): LedgerPage => ({
  organizationId: "org-a", generatedAt: "2026-10-03T10:00:00.000Z",
  filters: {
    limit: 25, cursor: null, workItemId: null, actorUserId: null,
    decision: null, includeMalformed: false,
  },
  entries, malformed: [], fetched: entries.length, matched: entries.length,
  nextCursor: null, coverage: "BOUNDED_RAW_AUDIT_PAGE", limitations: [],
});
const kinds = (...entries: LedgerEntry[]) =>
  inspectLedgerInsights(page(entries)).alerts.map(item => item.kind);
describe("bounded source audit sequence interpretation", () => {
  it("returns no warnings for a linked, consistent review chain", () => {
    const result = inspectLedgerInsights(page([row("a"), row("b")]));
    expect(result.counts.ERROR).toBe(0);
    expect(result.counts.REVIEW).toBe(0);
    expect(result.caseIdentities).toBe(1);
    expect(result.workIdentities).toBe(1);
  });
  it("refuses foreign tenant rows even from decoded source", () => {
    expect(() => inspectLedgerInsights(page([
      row("a", { organizationId: "foreign" }),
    ]))).toThrow(/Foreign event/);
  });
  it("flags a historical review revision without asserting failed remediation", () => {
    expect(kinds(row("a", { reviewedRevisionIsCurrent: false })))
      .toContain("HISTORICAL_WORK_REVISION");
  });
  it("shows unavailable work as source uncertainty", () => {
    expect(kinds(row("a", { currentWorkRevision: null })))
      .toContain("WORK_ITEM_UNAVAILABLE");
  });
  it("identifies a missing current review actor", () => {
    expect(kinds(row("a", { actorUserId: null })))
      .toContain("REVIEW_ACTOR_UNAVAILABLE");
  });
  it("does not characterize an out-of-page predecessor as deleted", () => {
    const result = inspectLedgerInsights(page([row("b", {
      predecessorInPage: false, predecessorChronologicallyPrior: null,
    })]));
    expect(result.byKind.REVIEW_PREDECESSOR_OUTSIDE_PAGE).toBe(1);
    expect(result.counts.UNKNOWN).toBe(1);
  });
  it("identifies reversed linked event times", () => {
    expect(kinds(row("b", { predecessorChronologicallyPrior: false })))
      .toContain("REVIEW_TIME_REVERSED");
  });
  it("detects missing rationale without creating one", () => {
    expect(kinds(row("a", { rationale: "" })))
      .toContain("REVIEW_RATIONALE_MISSING");
  });
  it("recognizes explicit reopen actions as informational", () => {
    const result = inspectLedgerInsights(page([
      row("a", { decision: "REOPEN" }),
    ]));
    expect(result.byKind.REVIEW_DECISION_REOPENED).toBe(1);
    expect(result.counts.INFO).toBe(1);
  });
  it("detects predecessor links crossing diagnostic identities", () => {
    expect(kinds(
      row("a"),
      row("b", { resourceId: "other", predecessorEventId: "a" }),
    )).toContain("REVIEW_CHAIN_CROSSES_CASE");
  });
  it("detects review revision decreasing in an event sequence", () => {
    expect(kinds(
      row("a", { revision: 3 }),
      row("b", { revision: 2 }),
    )).toContain("REVIEW_REVISION_DECREASED");
  });
  it("detects two case events sharing a recorded timestamp", () => {
    expect(kinds(row("a"), row("b", {
      occurredAt: "2026-10-01T10:00:00.000Z",
    }))).toContain("DUPLICATE_CASE_EVENT_TIME");
  });
  it("detects same revision decisions that fail to link", () => {
    expect(kinds(row("a"), row("b", {
      predecessorEventId: null, predecessorInPage: false,
    }))).toContain("MULTIPLE_DECISIONS_SAME_REVISION");
  });
  it("preserves source entries and returns sorted severe alerts", () => {
    const entries = [row("a"), row("b", {
      resourceId: "other", predecessorEventId: "a",
    })];
    const before = JSON.stringify(entries);
    const result = inspectLedgerInsights(page(entries));
    expect(result.alerts[0]?.severity).toBe("ERROR");
    expect(JSON.stringify(entries)).toBe(before);
  });
  it("quantifies bounded predecessor coverage without claiming global completeness", () => {
    const result = inspectLedgerInsights(page([row("b", {
      predecessorInPage: false,
      predecessorChronologicallyPrior: null,
    })]));
    expect(result.explicitPredecessorLinks).toBe(1);
    expect(result.linksAvailableOnPage).toBe(0);
    expect(result.predecessorsOutsidePage).toBe(1);
    expect(result.sourceCoverage).toBe("PAGE_WITH_OUTSIDE_PREDECESSORS");
  });
  it("counts current, historical and unavailable work revisions separately", () => {
    const result = inspectLedgerInsights(page([
      row("a"), row("b", { reviewedRevisionIsCurrent: false }),
      row("c", { currentWorkRevision: null, reviewedRevisionIsCurrent: null }),
    ]));
    expect(result.currentWorkRevisionMatches).toBe(1);
    expect(result.outdatedWorkRevisions).toBe(1);
    expect(result.missingCurrentWork).toBe(1);
  });
  it("returns a CSV with event and evidence references", () => {
    const result = inspectLedgerInsights(page([row("a", { actorUserId: null })]));
    const csv = ledgerInsightsCsv(result);
    expect(csv).toContain("REVIEW_ACTOR_UNAVAILABLE");
    expect(csv).toContain("relatedEventId");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
