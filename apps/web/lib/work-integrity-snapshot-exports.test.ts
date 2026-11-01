import { describe, expect, it } from "vitest";
import { buildCaseContinuityReport } from "./work-integrity-case-continuity";
import {
  snapshotCatalogCsv, snapshotTrendCsv, snapshotIncidentCsv,
  snapshotReleaseCsv, caseContinuityCsv, exportSnapshotReport,
} from "./work-integrity-snapshot-exports";
import { buildSnapshotCatalog } from "./work-integrity-snapshot-catalog";
import { buildSnapshotTrendReport } from "./work-integrity-snapshot-trends";
import { detectSnapshotIncidents } from "./work-integrity-snapshot-incidents";
import { assessSnapshotReleaseBatch } from "./work-integrity-snapshot-release";

const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
const continuityPolicy = {
  maxCapturesPerSource: 100, maxEvents: 1000, includeUnchangedEvents: false,
};
const trendPolicy = {
  maxCapturesPerSource: 100, maxAgeDays: 90, minimumTrendPoints: 2,
  stableAbsoluteThreshold: 0, requireCompleteForTrend: false,
};
const incidentPolicy = {
  maxCaptureGapDays: 1, criticalIncreaseThreshold: 1,
  reviewBacklogIncreaseThreshold: 1, reportDisappearance: true,
};
const releasePolicy = {
  maxAgeDays: 90, requireComplete: false, requireQualityClearance: false,
  requireReview: false, requireBaseline: false, minCases: 0,
};
describe("source-isolated case continuity", () => {
  it("supports empty capture collections", () => {
    const report = buildCaseContinuityReport([], tenant, continuityPolicy);
    expect(report.totalTrackedCases).toBe(0);
    expect(report.totalEvents).toBe(0);
  });
  it("tracks capture count for one source", () => {
    const report = buildCaseContinuityReport([capture(1), capture(2)],
      tenant, continuityPolicy);
    expect(report.sources[0]?.captures).toBe(2);
  });
  it("does not combine unrelated capture sources", () => {
    const report = buildCaseContinuityReport([
      capture(1), capture(2, "source-b"),
    ], tenant, continuityPolicy);
    expect(report.sources).toHaveLength(2);
  });
  it("sorts captures in chronological order", () => {
    const report = buildCaseContinuityReport([
      capture(3), capture(1), capture(2),
    ], tenant, continuityPolicy);
    expect(report.sources[0]?.firstCapturedAt).toContain("-01T");
    expect(report.sources[0]?.latestCapturedAt).toContain("-03T");
  });
  it("rejects cross-tenant captures", () => {
    expect(() => buildCaseContinuityReport([
      capture(1, "source-a", true, "tenant-b"),
    ], tenant, continuityPolicy)).toThrow(/Cross-organization/);
  });
  it("rejects duplicate source timestamps", () => {
    expect(() => buildCaseContinuityReport([
      capture(1), capture(1),
    ], tenant, continuityPolicy)).toThrow(/Duplicate/);
  });
  it("enforces source capture limits", () => {
    expect(() => buildCaseContinuityReport([
      capture(1), capture(2),
    ], tenant, { ...continuityPolicy, maxCapturesPerSource: 1 }))
      .toThrow(/limit/);
  });
  it("rejects invalid event limits", () => {
    expect(() => buildCaseContinuityReport([], tenant,
      { ...continuityPolicy, maxEvents: 0 })).toThrow(/Invalid/);
  });
  it("rejects missing authenticated organization", () => {
    expect(() => buildCaseContinuityReport([], "", continuityPolicy))
      .toThrow(/Authenticated/);
  });
  it("reports no case disappearance without observed case keys", () => {
    const report = buildCaseContinuityReport([
      capture(1), capture(2, "source-a", false),
    ], tenant, continuityPolicy);
    expect(report.sources[0]?.missing).toBe(0);
    expect(report.sources[0]?.indeterminate).toBe(0);
  });
});
describe("spreadsheet-safe snapshot exports", () => {
  it("exports catalog with UTF-8 BOM", () => {
    const catalog = buildSnapshotCatalog([capture(1)], tenant);
    expect(snapshotCatalogCsv(catalog).startsWith("\uFEFF")).toBe(true);
  });
  it("includes source identity in catalog rows", () => {
    const catalog = buildSnapshotCatalog([capture(1)], tenant);
    expect(snapshotCatalogCsv(catalog)).toContain('"source-a"');
  });
  it("neutralizes formula-leading source identifiers", () => {
    const catalog = buildSnapshotCatalog([capture(1, "=2+3")], tenant);
    expect(snapshotCatalogCsv(catalog)).toContain('"\'=2+3"');
  });
  it("neutralizes formula-leading organization identifiers", () => {
    const catalog = buildSnapshotCatalog([capture(1, "source-a", true, "=1+1")],
      "=1+1");
    expect(snapshotCatalogCsv(catalog)).toContain('"\'=1+1"');
  });
  it("escapes embedded double quotes", () => {
    const catalog = buildSnapshotCatalog([capture(1, 'source "quoted"')], tenant);
    expect(snapshotCatalogCsv(catalog)).toContain('"source ""quoted"""');
  });
  it("exports empty catalog with a header", () => {
    const catalog = buildSnapshotCatalog([], tenant);
    expect(snapshotCatalogCsv(catalog)).toContain('"organizationId","source"');
  });
  it("exports trend observations with metrics", () => {
    const trend = buildSnapshotTrendReport([capture(1), capture(2)],
      tenant, now, trendPolicy);
    expect(snapshotTrendCsv(trend)).toContain('"ACTIVE_CASES"');
  });
  it("exports incidents with severity and next action", () => {
    const incidents = detectSnapshotIncidents([capture(1), capture(3)],
      tenant, incidentPolicy);
    const csv = snapshotIncidentCsv(incidents);
    expect(csv).toContain('"SOURCE_GAP"');
    expect(csv).toContain('"WARNING"');
  });
  it("exports release gate decisions", () => {
    const release = assessSnapshotReleaseBatch([capture(1)],
      tenant, now, releasePolicy);
    const csv = snapshotReleaseCsv(release);
    expect(csv).toContain('"COVERAGE"');
    expect(csv).toContain('"MANIFEST"');
  });
  it("exports continuity with the declared schema", () => {
    const report = buildCaseContinuityReport([capture(1)],
      tenant, continuityPolicy);
    expect(caseContinuityCsv(report)).toContain('"caseKey"');
  });
  it("dispatches catalog CSV through the generic export function", () => {
    const report = buildSnapshotCatalog([capture(1)], tenant);
    expect(exportSnapshotReport("catalog", report)).toBe(snapshotCatalogCsv(report));
  });
  it("dispatches trend CSV through the generic export function", () => {
    const report = buildSnapshotTrendReport([capture(1), capture(2)],
      tenant, now, trendPolicy);
    expect(exportSnapshotReport("trends", report)).toBe(snapshotTrendCsv(report));
  });
  it("dispatches incident CSV through the generic export function", () => {
    const report = detectSnapshotIncidents([capture(1), capture(3)],
      tenant, incidentPolicy);
    expect(exportSnapshotReport("incidents", report)).toBe(snapshotIncidentCsv(report));
  });
  it("dispatches release CSV through the generic export function", () => {
    const report = assessSnapshotReleaseBatch([capture(1)],
      tenant, now, releasePolicy);
    expect(exportSnapshotReport("release-batch", report)).toBe(snapshotReleaseCsv(report));
  });
  it("dispatches continuity CSV through the generic export function", () => {
    const report = buildCaseContinuityReport([capture(1)],
      tenant, continuityPolicy);
    expect(exportSnapshotReport("continuity", report)).toBe(caseContinuityCsv(report));
  });
});
