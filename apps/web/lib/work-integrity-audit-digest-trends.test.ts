import { describe, expect, it } from "vitest";
import type { AuditDigest, AuditDigestBucket } from "./work-integrity-audit-digest";
import { analyzeAuditDigestTrends, auditTrendCsv } from "./work-integrity-audit-digest-trends";
const bucket = (day: string, recorded: number, extra: Partial<AuditDigestBucket> = {}): AuditDigestBucket => ({
  day, recorded, investigations: recorded, acknowledgements: 0,
  dismissals: 0, reopenings: 0, uniqueCases: recorded,
  uniqueWorkItems: recorded, actors: recorded ? 1 : 0,
  unknownActors: 0, staleReviews: 0, malformed: 0, ...extra,
});
const digest = (daily: AuditDigestBucket[], patch: Partial<AuditDigest> = {}): AuditDigest => ({
  organizationId: "tenant-a", generatedAt: "2026-11-01T12:00:00Z",
  from: "2026-10-29T00:00:00Z", to: "2026-11-01T12:00:00Z",
  rawRecordsRead: daily.reduce((s, d) => s + d.recorded, 0),
  historyTruncated: false, malformed: 0,
  recorded: daily.reduce((s, d) => s + d.recorded, 0),
  uniqueWorkItems: 0, uniqueCases: 0, reviewedByActors: 0, knownActorCount: 0, unattributedDecisionCount: 0,
  outdatedReviewCount: 0, historyCoverage: "BOUNDED_COMPLETE",
  decisions: { INVESTIGATE: 0, ACKNOWLEDGE: 0, DISMISS: 0, REOPEN: 0 },
  daily, actors: [], cases: [], limitations: [], ...patch,
});
const days = (values: number[]) =>
  values.map((count, index) => bucket(
    `2026-10-${String(index + 20).padStart(2, "0")}`, count,
  ));
describe("source-aware review activity trends", () => {
  it("does not claim improvement from zero review events", () => {
    const report = analyzeAuditDigestTrends(digest(days([0, 0, 0, 0])));
    expect(report.findings.some(x => x.signal === "NO_RECORDED_ACTIVITY")).toBe(true);
    expect(report.dailyRateRatio).toBeNull();
  });
  it("detects increasing recorded-review workload", () => {
    const report = analyzeAuditDigestTrends(digest(days([1, 1, 5, 6])));
    expect(report.findings.map(x => x.signal)).toContain("RISING_REVIEW_LOAD");
    expect(report.current.recorded).toBe(11);
  });
  it("detects falling recorded-review workload", () => {
    const report = analyzeAuditDigestTrends(digest(days([6, 5, 1, 1])));
    expect(report.findings.map(x => x.signal)).toContain("FALLING_REVIEW_LOAD");
  });
  it("normalizes by day when periods have different day counts", () => {
    const report = analyzeAuditDigestTrends(digest(days([2, 2, 2])));
    expect(report.prior.days).toBe(1);
    expect(report.current.days).toBe(2);
    expect(report.dailyRateRatio).toBe(1);
    expect(report.findings.map(x => x.signal)).toContain("STABLE_REVIEW_LOAD");
  });
  it("does not emit directional claims for truncated source history", () => {
    const report = analyzeAuditDigestTrends(digest(days([1, 1, 5, 6]), {
      historyTruncated: true,
    }));
    expect(report.findings.map(x => x.signal)).toContain("INCOMPLETE_HISTORY");
    expect(report.findings.map(x => x.signal)).not.toContain("RISING_REVIEW_LOAD");
  });
  it("flags malformed source rows separately", () => {
    const report = analyzeAuditDigestTrends(digest(days([1, 1]), {
      malformed: 2,
    }));
    expect(report.findings.map(x => x.signal)).toContain("MALFORMED_SOURCE_ROWS");
  });
  it("flags reopened reviews in the later part of the window", () => {
    const values = days([1, 1]);
    values[1] = { ...values[1]!, reopenings: 1 };
    const report = analyzeAuditDigestTrends(digest(values));
    expect(report.findings.map(x => x.signal)).toContain("REOPENING_ACTIVITY");
  });
  it("flags actors that are no longer retained", () => {
    const values = days([1, 1]);
    values[1] = { ...values[1]!, unknownActors: 1 };
    expect(analyzeAuditDigestTrends(digest(values)).findings.map(x => x.signal))
      .toContain("UNATTRIBUTED_REVIEWS");
  });
  it("flags reviews referring to old work revisions", () => {
    const values = days([1, 1]);
    values[1] = { ...values[1]!, staleReviews: 1 };
    expect(analyzeAuditDigestTrends(digest(values)).findings.map(x => x.signal))
      .toContain("OUTDATED_REVISION_ACTIVITY");
  });
  it("does not accept repeated daily source identities", () => {
    expect(() => analyzeAuditDigestTrends(digest([
      bucket("2026-10-30", 1), bucket("2026-10-30", 2),
    ]))).toThrow(/Duplicate daily/);
  });
  it("rejects negative source counts", () => {
    expect(() => analyzeAuditDigestTrends(digest([
      bucket("2026-10-30", -1),
    ]))).toThrow(/Invalid recorded/);
  });
  it("does not reorder or mutate source digest buckets", () => {
    const rows = days([4, 3, 2, 1]).reverse();
    const before = JSON.stringify(rows);
    analyzeAuditDigestTrends(digest(rows));
    expect(JSON.stringify(rows)).toBe(before);
  });
  it("exports bounded signals to a safe CSV", () => {
    const csv = auditTrendCsv(analyzeAuditDigestTrends(digest(days([1, 1, 5, 6]))));
    expect(csv).toContain("RISING_REVIEW_LOAD");
    expect(csv).toContain("priorCount");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
