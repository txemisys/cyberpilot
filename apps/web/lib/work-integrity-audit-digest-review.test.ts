import { describe, expect, it } from "vitest";
import type { AuditDigest } from "./work-integrity-audit-digest";
import { planAuditReviewWorkload, reviewWorkloadCsv } from "./work-integrity-audit-digest-review";
const digest = (patch: Partial<AuditDigest> = {}): AuditDigest => ({
  organizationId: "org-a",
  generatedAt: "2026-11-01T12:00:00.000Z",
  from: "2026-10-31T00:00:00.000Z", to: "2026-11-01T11:59:59.000Z",
  rawRecordsRead: 3, historyTruncated: false, malformed: 0,
  recorded: 3, uniqueWorkItems: 1, uniqueCases: 1, reviewedByActors: 1, knownActorCount: 1, unattributedDecisionCount: 0,
  outdatedReviewCount: 0, historyCoverage: "BOUNDED_COMPLETE",
  decisions: { INVESTIGATE: 2, ACKNOWLEDGE: 1, DISMISS: 0, REOPEN: 0 },
  daily: [{
    day: "2026-10-31", recorded: 3, investigations: 2,
    acknowledgements: 1, dismissals: 0, reopenings: 0,
    uniqueCases: 1, uniqueWorkItems: 1, actors: 1,
    unknownActors: 0, staleReviews: 0, malformed: 0,
  }],
  actors: [{
    actorUserId: "reviewer-1", recorded: 3,
    decisions: { INVESTIGATE: 2, ACKNOWLEDGE: 1 }, workItems: 1,
  }],
  cases: [{
    caseKey: JSON.stringify(["work-1", "DONE_WITHOUT_COMPLETION", "work-1"]),
    workItemId: "work-1", code: "DONE_WITHOUT_COMPLETION",
    resourceId: "work-1", events: 3, lastDecision: "ACKNOWLEDGE",
    lastEventId: "audit-3", lastAt: "2026-10-31T12:00:00.000Z",
    latestReviewedRevision: 2, currentWorkRevision: 2,
    currentlyReviewed: true,
  }],
  limitations: [], ...patch,
});
const kinds = (result: AuditDigest) =>
  planAuditReviewWorkload(result).items.map(item => item.kind);
describe("source-aware bounded audit activity follow-up planning", () => {
  it("creates no actions for a healthy bounded source", () => {
    expect(planAuditReviewWorkload(digest()).items).toEqual([]);
  });
  it("recommends recollecting capped source history", () => {
    expect(kinds(digest({ historyTruncated: true }))).toContain("AUDIT_SOURCE_TRUNCATED");
  });
  it("prioritizes malformed stored audit rows", () => {
    const plan = planAuditReviewWorkload(digest({ malformed: 2 }));
    expect(plan.items[0]?.kind).toBe("MALFORMED_AUDIT_EVENTS");
    expect(plan.sourceQualityItems).toBe(1);
  });
  it("distinguishes historical work review revisions", () => {
    const original = digest();
    const result = digest({
      cases: [{ ...original.cases[0]!, currentlyReviewed: false }],
    });
    expect(kinds(result)).toContain("HISTORICAL_REVIEW_REVISION");
  });
  it("flags unavailable original work without inventing a revision", () => {
    const original = digest();
    const result = digest({
      cases: [{ ...original.cases[0]!, currentWorkRevision: null,
        currentlyReviewed: null }],
    });
    expect(kinds(result)).toContain("UNAVAILABLE_WORK_ITEM");
  });
  it("recognizes reopened diagnostics as needing a followup", () => {
    const original = digest();
    expect(kinds(digest({
      cases: [{ ...original.cases[0]!, lastDecision: "REOPEN" }],
    }))).toContain("REOPENED_DIAGNOSTIC");
  });
  it("flags repeated decisions only at configured thresholds", () => {
    const result = planAuditReviewWorkload(digest(), {
      repeatedCaseReviewThreshold: 3,
    });
    expect(result.byKind.MULTIPLE_HUMAN_DECISIONS).toBe(1);
  });
  it("keeps unusual review activity operational rather than an incident", () => {
    const result = planAuditReviewWorkload(digest(), {
      dailyActivityThreshold: 3,
    });
    expect(result.byKind.HIGH_REVIEW_ACTIVITY).toBe(1);
    expect(result.items.find(item => item.kind === "HIGH_REVIEW_ACTIVITY")
      ?.explanation).toContain("configured threshold");
  });
  it("flags missing actor references by day", () => {
    const original = digest();
    const result = digest({
      daily: [{ ...original.daily[0]!, unknownActors: 2 }],
    });
    expect(kinds(result)).toContain("ACTOR_REFERENCE_MISSING");
  });
  it("flags a missing actor on individual source aggregation", () => {
    const result = digest({
      actors: [{ actorUserId: null, recorded: 4,
        decisions: { INVESTIGATE: 4 }, workItems: 2 }],
    });
    expect(kinds(result)).toContain("UNATTRIBUTED_DECISION_VOLUME");
  });
  it("rejects invalid bounded plan options", () => {
    expect(() => planAuditReviewWorkload(digest(), { limit: 0 })).toThrow();
    expect(() => planAuditReviewWorkload(digest(), {
      dailyActivityThreshold: 0,
    })).toThrow();
    expect(() => planAuditReviewWorkload(digest(), {
      repeatedCaseReviewThreshold: 101,
    })).toThrow();
  });
  it("counts all matching actions independently of response limit", () => {
    const original = digest();
    const report = digest({
      historyTruncated: true, malformed: 2,
      cases: [{ ...original.cases[0]!, currentlyReviewed: false }],
    });
    const result = planAuditReviewWorkload(report, { limit: 1 });
    expect(result.items).toHaveLength(1);
    expect(result.itemCount).toBeGreaterThan(1);
    expect(result.omittedItems).toBe(result.itemCount - 1);
  });
  it("never creates assignments or automatic closure from an audit recommendation", () => {
    const result = planAuditReviewWorkload(digest({ malformed: 1 }));
    expect(result.items.every(item => item.cannotBeAutoClosed)).toBe(true);
    expect(result.limitations.join(" ")).toContain("never written into the task database");
  });
  it("exports a safe human-readable action plan CSV", () => {
    const csv = reviewWorkloadCsv(planAuditReviewWorkload(digest({
      malformed: 1,
    })));
    expect(csv).toContain("MALFORMED_AUDIT_EVENTS");
    expect(csv).toContain("cannotBeAutoClosed");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
