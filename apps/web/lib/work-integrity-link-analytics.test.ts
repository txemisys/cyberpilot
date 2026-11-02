import { describe, expect, it } from "vitest";
import {
  analyzeIntegrityLinkEvents, filterLinkAnalyticsEvents, parseLinkAnalyticsQuery,
  sortLinkAnalyticsEvents, type LinkAnalyticsQuery,
} from "./work-integrity-link-analytics";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";

const time = "2026-11-01T10:00:00.000Z";
function link(
  auditId: string, caseKey = "case-1", workItemId = "work-1",
  occurredAt = time, actorUserId: string | null = "user-1",
): IntegrityLinkHistoryEvent {
  return {
    auditId, originalAuditId: null, action: "LINK",
    captureId: "capture-1", caseKey, workItemId, occurredAt, actorUserId,
  };
}
function unlink(
  auditId: string, originalAuditId: string, occurredAt = "2026-11-02T10:00:00.000Z",
): IntegrityLinkHistoryEvent {
  return {
    ...link(auditId, "case-1", "work-1", occurredAt),
    action: "UNLINK", originalAuditId,
  };
}
const defaults: LinkAnalyticsQuery = {
  filter: {}, sort: "newest", offset: 0, limit: 100,
};
describe("integrity association analytics", () => {
  it("returns empty totals and collections for an empty history", () => {
    const report = analyzeIntegrityLinkEvents([]);
    expect(report.summary.totalEvents).toBe(0);
    expect(report.summary.activeLinks).toBe(0);
    expect(report.summary.firstEventAt).toBeNull();
    expect(report.cases).toEqual([]);
    expect(report.workItems).toEqual([]);
    expect(report.actors).toEqual([]);
    expect(report.days).toEqual([]);
    expect(report.events).toEqual([]);
    expect(report.pagination.hasMore).toBe(false);
  });
  it("counts active and withdrawn links without deleting audit history", () => {
    const report = analyzeIntegrityLinkEvents([
      unlink("withdrawal-1", "link-1"),
      link("link-2"), link("link-1"),
    ]);
    expect(report.summary).toMatchObject({
      totalEvents: 3, linksCreated: 2, withdrawals: 1,
      activeLinks: 1, withdrawnLinks: 1,
      distinctCases: 1, distinctWorkItems: 1, distinctActors: 1,
      orphanWithdrawals: 0, duplicateWithdrawals: 0,
    });
    expect(report.cases[0]).toMatchObject({
      totalLinks: 2, activeLinks: 1, withdrawnLinks: 1,
    });
    expect(report.workItems[0]).toMatchObject({
      totalLinks: 2, activeLinks: 1, withdrawnLinks: 1,
    });
  });
  it("reports orphan withdrawals that cannot be matched to a link", () => {
    const report = analyzeIntegrityLinkEvents([unlink("withdrawal-1", "missing")]);
    expect(report.summary.orphanWithdrawals).toBe(1);
    expect(report.integrity.orphanWithdrawalIds).toEqual(["withdrawal-1"]);
    expect(report.summary.activeLinks).toBe(0);
  });
  it("reports withdrawals without original identifiers", () => {
    const report = analyzeIntegrityLinkEvents([{
      ...unlink("withdrawal-1", "link-1"), originalAuditId: null,
    }]);
    expect(report.integrity.orphanWithdrawalIds).toEqual(["withdrawal-1"]);
  });
  it("detects duplicate withdrawals for one immutable link", () => {
    const report = analyzeIntegrityLinkEvents([
      link("link-1"), unlink("withdrawal-1", "link-1"),
      unlink("withdrawal-2", "link-1"),
    ]);
    expect(report.summary.duplicateWithdrawals).toBe(1);
    expect(report.integrity.duplicateWithdrawalIds).toEqual(["withdrawal-2"]);
    expect(report.summary.withdrawnLinks).toBe(1);
  });
  it("does not confuse links to the same work item", () => {
    const report = analyzeIntegrityLinkEvents([
      link("link-1"), link("link-2"), unlink("withdrawal-1", "link-1"),
    ]);
    expect(report.summary.activeLinks).toBe(1);
    expect(report.summary.withdrawnLinks).toBe(1);
  });
  it("groups different cases and work items independently", () => {
    const report = analyzeIntegrityLinkEvents([
      link("link-1", "case-b", "work-b"),
      link("link-2", "case-a", "work-a"),
      link("link-3", "case-a", "work-b"),
    ]);
    expect(report.summary.distinctCases).toBe(2);
    expect(report.summary.distinctWorkItems).toBe(2);
    expect(report.cases.map(x => x.caseKey)).toEqual(["case-a", "case-b"]);
    expect(report.cases[0]?.workItemIds).toEqual(["work-a", "work-b"]);
    expect(report.workItems.find(x => x.workItemId === "work-b")?.caseKeys)
      .toEqual(["case-a", "case-b"]);
  });
  it("groups actor activity without inventing actor identities", () => {
    const report = analyzeIntegrityLinkEvents([
      link("link-1", "case-1", "work-1", time, null),
      link("link-2", "case-1", "work-1", time, "user-2"),
      unlink("withdrawal-1", "link-1"),
    ]);
    expect(report.summary.distinctActors).toBe(3);
    expect(report.actors.find(x => x.actorUserId === null)?.linksCreated).toBe(1);
    expect(report.actors.find(x => x.actorUserId === "user-1")?.withdrawals).toBe(1);
  });
  it("groups events by UTC calendar day", () => {
    const report = analyzeIntegrityLinkEvents([
      link("link-1"), unlink("withdrawal-1", "link-1"),
    ]);
    expect(report.days).toEqual([
      { day: "2026-11-01", linksCreated: 1, withdrawals: 0 },
      { day: "2026-11-02", linksCreated: 0, withdrawals: 1 },
    ]);
  });
  it("sorts by time and audit identifier deterministically", () => {
    const events = [link("link-a"), link("link-c"), link("link-b")];
    expect(sortLinkAnalyticsEvents(events, "newest").map(x => x.auditId))
      .toEqual(["link-c", "link-b", "link-a"]);
    expect(sortLinkAnalyticsEvents(events, "oldest").map(x => x.auditId))
      .toEqual(["link-a", "link-b", "link-c"]);
    expect(events.map(x => x.auditId)).toEqual(["link-a", "link-c", "link-b"]);
  });
  it("sorts by case and work item with stable tie breakers", () => {
    const events = [
      link("link-2", "case-b", "work-a"),
      link("link-1", "case-a", "work-b"),
    ];
    expect(sortLinkAnalyticsEvents(events, "case").map(x => x.auditId))
      .toEqual(["link-1", "link-2"]);
    expect(sortLinkAnalyticsEvents(events, "work").map(x => x.auditId))
      .toEqual(["link-2", "link-1"]);
  });
  it("filters events without altering global summary totals", () => {
    const events = [link("link-1"), unlink("withdrawal-1", "link-1")];
    const report = analyzeIntegrityLinkEvents(events, {
      ...defaults, filter: { action: "UNLINK" },
    });
    expect(report.events.map(x => x.auditId)).toEqual(["withdrawal-1"]);
    expect(report.summary.totalEvents).toBe(2);
    expect(report.pagination.total).toBe(1);
  });
  it("filters by actor, case, work and inclusive time bounds", () => {
    const events = [
      link("link-1", "case-a", "work-a", time, "user-a"),
      link("link-2", "case-b", "work-b", "2026-11-02T10:00:00.000Z", "user-b"),
    ];
    expect(filterLinkAnalyticsEvents(events, {
      caseKey: "case-a", workItemId: "work-a", actorUserId: "user-a",
      since: time, until: time,
    }).map(x => x.auditId)).toEqual(["link-1"]);
  });
  it("supports bounded offsets and exposes whether further events exist", () => {
    const events = [link("link-1"), link("link-2"), link("link-3")];
    const report = analyzeIntegrityLinkEvents(events, {
      ...defaults, offset: 1, limit: 1,
    });
    expect(report.events.map(x => x.auditId)).toEqual(["link-2"]);
    expect(report.pagination).toEqual({
      offset: 1, limit: 1, total: 3, hasMore: true,
    });
    const last = analyzeIntegrityLinkEvents(events, {
      ...defaults, offset: 2, limit: 1,
    });
    expect(last.pagination.hasMore).toBe(false);
  });
  it("accepts a complete validated analytics query", () => {
    expect(parseLinkAnalyticsQuery({
      action: "LINK", caseKey: "case-1", workItemId: "work-1",
      actorUserId: "user-1", sort: "oldest", offset: 5, limit: 20,
      since: time, until: "2026-11-02T10:00:00.000Z",
    })).toMatchObject({
      filter: { action: "LINK", caseKey: "case-1", workItemId: "work-1" },
      sort: "oldest", offset: 5, limit: 20,
    });
  });
  it("defaults pagination and ordering for an empty query", () => {
    expect(parseLinkAnalyticsQuery({})).toEqual(defaults);
  });
  it.each([
    null, [], "bad", { unknown: 1 }, { sort: "random" },
    { action: "DELETE" }, { offset: -1 }, { limit: 0 },
    { limit: 1001 }, { offset: 1.2 }, { limit: Infinity },
    { caseKey: "" }, { caseKey: "bad\ncase" },
    { workItemId: "" }, { actorUserId: "bad\tactor" },
    { since: "yesterday" }, { until: "2026-11-01" },
    { since: "2026-11-03T10:00:00.000Z", until: time },
  ])("rejects malformed analytics queries: %j", value => {
    expect(() => parseLinkAnalyticsQuery(value)).toThrow();
  });
});
