import { describe, expect, it } from "vitest";
import type { AuditDigest } from "./work-integrity-audit-digest";
import { reconcileAuditDigest, auditReconciliationCsv } from "./work-integrity-audit-digest-reconciliation";

const sample = (changes: Partial<AuditDigest> = {}): AuditDigest => ({
  organizationId: "org-a", generatedAt: "2026-11-01T10:00:00Z",
  from: "2026-10-30T00:00:00Z", to: "2026-11-01T09:00:00Z",
  rawRecordsRead: 2, recorded: 2, malformed: 0,
  historyTruncated: false, historyCoverage: "BOUNDED_COMPLETE",
  uniqueWorkItems: 1, uniqueCases: 1, reviewedByActors: 1,
  knownActorCount: 1, unattributedDecisionCount: 0, outdatedReviewCount: 0,
  decisions: { INVESTIGATE: 1, ACKNOWLEDGE: 1, DISMISS: 0, REOPEN: 0 },
  daily: [{
    day: "2026-10-31", recorded: 2, investigations: 1,
    acknowledgements: 1, dismissals: 0, reopenings: 0,
    uniqueCases: 1, uniqueWorkItems: 1, actors: 1,
    unknownActors: 0, staleReviews: 0, malformed: 0,
  }],
  actors: [{
    actorUserId: "user-a", recorded: 2, workItems: 1,
    decisions: { INVESTIGATE: 1, ACKNOWLEDGE: 1 },
  }],
  cases: [{
    caseKey: JSON.stringify(["work-a", "DONE_WITHOUT_COMPLETION", "work-a"]),
    workItemId: "work-a", code: "DONE_WITHOUT_COMPLETION",
    resourceId: "work-a", events: 2, lastDecision: "ACKNOWLEDGE",
    lastEventId: "event-b", lastAt: "2026-10-31T12:00:00Z",
    latestReviewedRevision: 2, currentWorkRevision: 2,
    currentlyReviewed: true,
  }],
  limitations: [], ...changes,
});
const codes = (digest: AuditDigest) => reconcileAuditDigest(digest).issues.map(x => x.code);
describe("reconcile source-derived audit report", () => {
  it("accepts a consistent bounded audit summary", () => {
    const result = reconcileAuditDigest(sample());
    expect(result.internallyConsistent).toBe(true);
    expect(result.sourceIsComplete).toBe(true);
    expect(result.issues).toHaveLength(0);
  });
  it("rejects missing trusted organization", () => {
    expect(() => reconcileAuditDigest(sample({ organizationId: "" }))).toThrow();
  });
  it("detects mismatched decision totals", () => {
    expect(codes(sample({ recorded: 3 }))).toContain("DECISION_TOTAL_MISMATCH");
  });
  it("detects missing raw record accounting", () => {
    expect(codes(sample({ rawRecordsRead: 3 }))).toContain("SOURCE_ROW_ACCOUNTING_MISMATCH");
  });
  it("distinguishes malformed source coverage", () => {
    const result = reconcileAuditDigest(sample({
      malformed: 1, rawRecordsRead: 3, historyCoverage: "MALFORMED",
      daily: [{ ...sample().daily[0]!, malformed: 1 }],
    }));
    expect(result.sourceIsComplete).toBe(false);
    expect(result.issues).toHaveLength(0);
  });
  it("reports source truncation inconsistency", () => {
    expect(codes(sample({ historyTruncated: true })))
      .toContain("COVERAGE_FLAG_INCONSISTENCY");
  });
  it("detects duplicate daily identities", () => {
    const day = sample().daily[0]!;
    expect(codes(sample({ daily: [day, day] }))).toContain("DUPLICATE_DAY");
  });
  it("detects impossible negative daily values", () => {
    expect(codes(sample({
      daily: [{ ...sample().daily[0]!, recorded: -1 }],
    }))).toContain("INVALID_DAILY_METRIC");
  });
  it("detects malformed daily decisions breakdown", () => {
    expect(codes(sample({
      daily: [{ ...sample().daily[0]!, acknowledgements: 0 }],
    }))).toContain("DAILY_TOTAL_MISMATCH");
  });
  it("detects duplicate case identities", () => {
    const item = sample().cases[0]!;
    expect(codes(sample({ cases: [item, item] })))
      .toContain("DUPLICATE_CASE_IDENTITY");
  });
  it("detects case-review revision contradictions", () => {
    expect(codes(sample({
      cases: [{ ...sample().cases[0]!, currentlyReviewed: false }],
    }))).toContain("CASE_REVISION_INCONSISTENCY");
  });
  it("rejects current review claims when work is absent", () => {
    expect(codes(sample({
      cases: [{ ...sample().cases[0]!, currentWorkRevision: null }],
    }))).toContain("CASE_REVISION_INCONSISTENCY");
  });
  it("detects duplicate actor identities", () => {
    const actor = sample().actors[0]!;
    expect(codes(sample({ actors: [actor, actor] })))
      .toContain("DUPLICATE_ACTOR_IDENTITY");
  });
  it("detects invalid actor subtotals", () => {
    expect(codes(sample({
      actors: [{ ...sample().actors[0]!, recorded: 3 }],
    }))).toContain("INVALID_ACTOR_METRIC");
  });
  it("detects mismatched retained actor counts", () => {
    expect(codes(sample({ knownActorCount: 0 })))
      .toContain("ACTOR_COUNT_MISMATCH");
  });
  it("detects attributed and outdated count drift", () => {
    expect(codes(sample({ unattributedDecisionCount: 1 })))
      .toContain("UNKNOWN_ACTOR_MISMATCH");
    expect(codes(sample({ outdatedReviewCount: 1 })))
      .toContain("OUTDATED_COUNT_MISMATCH");
  });
  it("detects malformed totals not represented in daily buckets", () => {
    expect(codes(sample({ malformed: 2 }))).toContain("MALFORMED_COUNT_MISMATCH");
  });
  it("detects reversed period chronology", () => {
    expect(codes(sample({
      from: "2026-11-02T00:00:00Z",
    }))).toContain("INVALID_DATE_ORDER");
  });
  it("preserves source data without mutation", () => {
    const data = sample();
    const before = JSON.stringify(data);
    reconcileAuditDigest(data);
    expect(JSON.stringify(data)).toBe(before);
  });
  it("exports bounded discrepancies as escaped CSV", () => {
    const csv = auditReconciliationCsv(reconcileAuditDigest(sample({ recorded: 3 })));
    expect(csv).toContain("DECISION_TOTAL_MISMATCH");
    expect(csv).toContain("recommendedAction");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
