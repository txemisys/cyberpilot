import { describe, expect, it } from "vitest";
import type { CaseRow } from "./work-integrity-cases";
import { parseCaseSnapshot, compareCaseSnapshots } from "./work-integrity-snapshots";
import { caseDimensions, sliceCases, groupCases, facetCases, trendCases, caseCohorts,
  changedCaseRows, highPriorityCases } from "./work-integrity-analytics";
import { buildCaseReport, caseReportCsv, caseReportJson, caseReportMarkdown,
  caseReportDigest, caseRiskBucket, riskBucketSummary, caseCodeSummary } from "./work-integrity-reporting";
import { normalizeSnapshotSeries, caseHistory, summarizeSnapshotSeries,
  caseTransitionMatrix, casePersistenceDistribution, workItemHistories } from "./work-integrity-series";
import { evaluateCaseAlerts, evaluateDeltaAlerts, operationalRecommendations,
  validateCaseAlertRule, caseMatchesAlertRule, compareAndAlert } from "./work-integrity-alerts";
import { exportSnapshotEnvelope, importSnapshotEnvelope, parseSnapshotEnvelope,
  snapshotEnvelopeJson, parseSnapshotJson, buildSnapshotBatch, batchToSnapshots,
  envelopeCoverage, snapshotCaseIndex, mergeSnapshotPages } from "./work-integrity-interchange";

const makeRow = (id: string, changes: Partial<CaseRow> = {}): CaseRow => ({
  key: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
  workItemId: id, resourceId: id, code: "DONE_WITHOUT_COMPLETION",
  taskStatus: "DONE", taskRevision: 1, severity: "attention",
  diagnostic: "Missing completion timestamp", recommendation: "Review",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
  ...changes,
});
const a = makeRow("work-a");
const b = makeRow("work-b", { severity: "critical", state: "STALE", reviewEventId: "event-b" });
const c = makeRow("work-c", { severity: "info", state: "INVESTIGATING", reviewEventId: "event-c" });
const d = makeRow("work-d", { severity: null, state: "NO_LONGER_DETECTED", historicalOnly: true });
const rows = [a, b, c, d];
const snapshot = (items: CaseRow[], complete = true, at = "2026-10-31T12:00:00.000Z") =>
  parseCaseSnapshot({ organizationId: "tenant-a", source: "offline-test",
    capturedAt: at, complete, cases: items });
const before = snapshot([a, b]);
const after = snapshot([a, c, d], true, "2026-10-31T13:00:00.000Z");
const comparison = compareCaseSnapshots(before, after);
const meta = (count: number, nextCursor: string | null = null) => ({
  scannedWorkItems: count, returnedCases: count, nextCursor, limitations: [] as string[],
});
const alertRule = {
  id: "unreviewed", name: "Unreviewed cases", enabled: true,
  states: ["UNREVIEWED"] as Array<CaseRow["state"]>,
  severities: [] as Array<CaseRow["severity"]>, codes: [] as string[],
  requireCompleteCoverage: false, onlyUnreviewed: true,
  minMatchingCases: 1, maxMatchingCases: null,
};
describe("case dimensions and facets", () => {
  it("counts states and severity exactly", () => {
    const result = caseDimensions(rows);
    expect(result.total).toBe(4);
    expect(result.byState.UNREVIEWED).toBe(1);
    expect(result.byState.STALE).toBe(1);
    expect(result.bySeverity.critical).toBe(1);
    expect(result.bySeverity.none).toBe(1);
    expect(result.reviewed).toBe(2);
    expect(result.historical).toBe(1);
  });
  it("counts critical unreviewed independently of stale critical", () => {
    expect(caseDimensions(rows).criticalUnreviewed).toBe(0);
    expect(caseDimensions([makeRow("x", { severity: "critical" })]).criticalUnreviewed).toBe(1);
  });
  it("filters by state", () => expect(sliceCases(rows, { states: ["STALE"] })).toEqual([b]));
  it("filters by severity", () => expect(sliceCases(rows, { severities: [null] })).toEqual([d]));
  it("filters by code", () => expect(sliceCases(rows, { codes: ["OTHER"] })).toEqual([]));
  it("filters by work item", () => expect(sliceCases(rows, { workItemIds: ["work-a"] })).toEqual([a]));
  it("filters reviewed cases", () => expect(sliceCases(rows, { reviewed: true })).toEqual([b, c]));
  it("filters historical cases", () => expect(sliceCases(rows, { historical: true })).toEqual([d]));
  it("filters partial coverage", () => {
    expect(sliceCases([a, { ...b, completeCoverage: false }], { completeCoverage: false })).toHaveLength(1);
  });
  it("filters case text", () => expect(sliceCases(rows, { text: "WORK-C" })).toEqual([c]));
  it("returns stable code grouping", () => {
    expect(groupCases(rows, "code")[0]?.count).toBe(4);
  });
  it("groups by work item", () => expect(groupCases(rows, "workItemId")).toHaveLength(4));
  it("produces all facet dimensions", () => {
    expect(facetCases(rows).map(x => x.dimension)).toEqual(["state", "severity", "code", "workItemId"]);
  });
  it("orders high priority cases", () => expect(highPriorityCases(rows, 2)[0]?.key).toBe(b.key));
  it("rejects invalid priority limits", () => expect(() => highPriorityCases(rows, -1)).toThrow());
  it("calculates cohorts", () => {
    const cohorts = caseCohorts(comparison, "state");
    expect(cohorts.find(x => x.cohort === "STALE")?.exited).toBe(1);
  });
  it("calculates trend deltas", () => {
    const trend = trendCases(before, after, comparison);
    expect(trend.change.total).toBe(1);
    expect(trend.caseChangeCounts.CLEARED).toBe(1);
  });
  it("rejects cross tenant trend inputs", () => {
    const other = snapshot([]);
    expect(() => trendCases({ ...other, organizationId: "other" }, after, comparison)).toThrow();
  });
  it("selects changed rows", () => expect(changedCaseRows(comparison)).toHaveLength(3));
});
describe("report serialization and summaries", () => {
  const report = buildCaseReport(before, after, comparison);
  it("preserves schema and tenant", () => {
    expect(report.schemaVersion).toBe(1);
    expect(report.organizationId).toBe("tenant-a");
  });
  it("serializes JSON", () => expect(JSON.parse(caseReportJson(report)).counts.NEW).toBe(2));
  it("serializes CSV with CRLF", () => expect(caseReportCsv(report)).toContain("\r\n"));
  it("serializes Markdown", () => expect(caseReportMarkdown(report)).toContain("## Change summary"));
  it("includes limitations", () => expect(report.limitations.length).toBeGreaterThan(1));
  it("supports row limits", () => expect(buildCaseReport(before, after, comparison, { maxRows: 1 }).changes).toHaveLength(1));
  it("rejects invalid limits", () => expect(() => buildCaseReport(before, after, comparison, { maxRows: -1 })).toThrow());
  it("rejects tenant mismatch", () => expect(() => buildCaseReport(
    { ...before, organizationId: "other" }, after, comparison)).toThrow());
  it("counts digest", () => expect(caseReportDigest(report).totalAfter).toBe(3));
  it("classifies stale review", () => expect(caseRiskBucket(b)).toBe("STALE_REVIEW"));
  it("classifies historical", () => expect(caseRiskBucket(d)).toBe("HISTORICAL"));
  it("summarizes risk", () => expect(riskBucketSummary(rows).STALE_REVIEW).toBe(1));
  it("summarizes codes", () => expect(caseCodeSummary(rows)[0]?.cases).toBe(4));
  it("neutralizes CSV formula injection", () => {
    const injected = makeRow("=HYPERLINK", {
      key: JSON.stringify(["=HYPERLINK", "DONE_WITHOUT_COMPLETION", "=HYPERLINK"]),
    });
    const first = snapshot([injected]);
    const second = snapshot([]);
    const exported = caseReportCsv(buildCaseReport(first, second, compareCaseSnapshots(first, second)));
    expect(exported).toContain("'=HYPERLINK");
  });
});
describe("multi-capture histories", () => {
  const series = normalizeSnapshotSeries([after, before]);
  const summary = summarizeSnapshotSeries(series);
  it("sorts captures", () => expect(series.snapshots[0]?.capturedAt).toBe(before.capturedAt));
  it("rejects duplicate timestamps", () => expect(() => normalizeSnapshotSeries([before, before])).toThrow());
  it("rejects cross-tenant captures", () => expect(() => normalizeSnapshotSeries([
    before, { ...after, organizationId: "other" },
  ])).toThrow());
  it("rejects excessive captures", () => expect(() => normalizeSnapshotSeries([before, after], 1)).toThrow());
  it("tracks presence and absence", () => {
    expect(caseHistory(series, b.key).observations.map(x => x.present)).toEqual([true, false]);
  });
  it("tracks latest severity", () => expect(caseHistory(series, c.key).latestSeverity).toBe("info"));
  it("tracks observed streak", () => expect(caseHistory(series, a.key).longestObservedStreak).toBe(2));
  it("counts intervals", () => expect(summary.intervals).toHaveLength(1));
  it("counts transitions", () => expect(caseTransitionMatrix(summary).observed).toBeGreaterThan(0));
  it("calculates persistence", () => expect(casePersistenceDistribution(summary).length).toBeGreaterThan(0));
  it("groups work item histories", () => expect(workItemHistories(summary)).toHaveLength(4));
  it("retains uncertainty for partial captures", () => {
    const partial = normalizeSnapshotSeries([before, { ...after, complete: false }]);
    expect(caseHistory(partial, b.key).observations.at(-1)?.present).toBeNull();
  });
});
describe("operational alert evaluation", () => {
  it("validates configured rules", () => expect(validateCaseAlertRule(alertRule).id).toBe("unreviewed"));
  it("rejects zero thresholds", () => expect(() => validateCaseAlertRule({
    ...alertRule, minMatchingCases: 0,
  })).toThrow());
  it("rejects invalid ranges", () => expect(() => validateCaseAlertRule({
    ...alertRule, maxMatchingCases: 0,
  })).toThrow());
  it("matches unreviewed cases", () => expect(caseMatchesAlertRule(a, alertRule)).toBe(true));
  it("excludes reviewed cases", () => expect(caseMatchesAlertRule(b, alertRule)).toBe(false));
  it("triggers on complete snapshots", () => {
    expect(evaluateCaseAlerts(after, [alertRule]).triggered).toBe(1);
  });
  it("withholds incomplete snapshot alert verdicts", () => {
    expect(evaluateCaseAlerts({ ...after, complete: false }, [alertRule]).indeterminate).toBe(1);
  });
  it("rejects duplicate rule identifiers", () => {
    expect(() => evaluateCaseAlerts(after, [alertRule, alertRule])).toThrow();
  });
  it("triggers delta alert on new cases", () => {
    expect(evaluateDeltaAlerts(comparison, [{
      id: "new", name: "New cases", enabled: true, kinds: ["NEW"],
      minCount: 1, requireCompleteComparison: true,
    }])[0]?.triggered).toBe(true);
  });
  it("produces operational recommendations", () => {
    expect(operationalRecommendations(after).some(x => x.category === "UNREVIEWED")).toBe(true);
  });
  it("combines alerts and comparisons", () => {
    expect(compareAndAlert(before, after, [alertRule], []).comparison.counts.NEW).toBe(2);
  });
});
describe("snapshot interchange", () => {
  const envelope = exportSnapshotEnvelope(before, meta(2));
  it("round trips envelope", () => expect(parseSnapshotEnvelope(envelope).cases).toHaveLength(2));
  it("round trips JSON", () => expect(parseSnapshotJson(snapshotEnvelopeJson(envelope), "tenant-a").snapshot.cases).toHaveLength(2));
  it("rejects wrong tenant", () => expect(() => importSnapshotEnvelope(envelope, "other")).toThrow());
  it("rejects invalid schema", () => expect(() => parseSnapshotEnvelope({ ...envelope, schemaVersion: 2 })).toThrow());
  it("rejects mismatched count", () => expect(() => parseSnapshotEnvelope({
    ...envelope, metadata: { ...envelope.metadata, returnedCases: 1 },
  })).toThrow());
  it("rejects invalid JSON", () => expect(() => parseSnapshotJson("{", "tenant-a")).toThrow());
  it("rejects oversize JSON", () => expect(() => parseSnapshotJson("x".repeat(10_000_001), "tenant-a")).toThrow());
  it("reports complete coverage", () => expect(envelopeCoverage(envelope).complete).toBe(true));
  it("reports pending continuation", () => {
    const pending = exportSnapshotEnvelope(before, meta(2, "next"));
    expect(envelopeCoverage(pending).continuationPending).toBe(true);
  });
  it("builds a batch", () => {
    const second = exportSnapshotEnvelope(after, meta(3));
    expect(buildSnapshotBatch([second, envelope]).totalCases).toBe(5);
  });
  it("converts batches to snapshots", () => {
    const batch = buildSnapshotBatch([envelope]);
    expect(batchToSnapshots(batch)[0]?.cases).toHaveLength(2);
  });
  it("rejects cross tenant batches", () => {
    expect(() => buildSnapshotBatch([envelope, { ...envelope, organizationId: "other" }])).toThrow();
  });
  it("indexes cases by stable key", () => expect(snapshotCaseIndex(before).get(a.key)).toEqual(a));
  it("rejects overlapping page keys", () => expect(() => mergeSnapshotPages([envelope, envelope])).toThrow());
  it("merges disjoint pages", () => {
    const other = exportSnapshotEnvelope(snapshot([c], true, before.capturedAt), meta(1));
    expect(mergeSnapshotPages([envelope, other]).cases).toHaveLength(3);
  });
});
