import { describe, expect, it } from "vitest";
import { buildSnapshotTrendReport } from "./work-integrity-snapshot-trends";
const tenant = "tenant-a";
const now = "2026-11-01T12:00:00.000Z";
const policy = {
  maxCapturesPerSource: 10, maxAgeDays: 90,
  minimumTrendPoints: 2, stableAbsoluteThreshold: 0,
  requireCompleteForTrend: false,
};
function capture(day: number, source = "source-a", complete = true,
  organizationId = tenant) {
  return {
    organizationId, source, complete, cases: [],
    capturedAt: `2026-10-${String(day).padStart(2, "0")}T12:00:00.000Z`,
  };
}
describe("rolling snapshot trends", () => {
  it("produces all six diagnostic and quality metric series", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(2)], tenant, now, policy);
    expect(result.sources[0]?.metrics).toHaveLength(6);
    expect(result.sourceCount).toBe(1);
  });
  it("reports insufficient points for single captures", () => {
    const result = buildSnapshotTrendReport([capture(1)], tenant, now, policy);
    expect(result.sources[0]?.metrics.every(m => m.direction === "INSUFFICIENT"))
      .toBe(true);
  });
  it("uses a stable direction for unchanged metrics", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(2)], tenant, now, policy);
    expect(result.sources[0]?.metrics.every(m => m.direction === "STABLE")).toBe(true);
  });
  it("tracks incomplete capture counts", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(2, "source-a", false)],
      tenant, now, policy);
    expect(result.sources[0]?.incompleteCaptures).toBe(1);
  });
  it("excludes incomplete captures from strict trends", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(2, "source-a", false)],
      tenant, now, { ...policy, requireCompleteForTrend: true });
    expect(result.sources[0]?.metrics[0]?.points).toHaveLength(1);
  });
  it("preserves source isolation for trend series", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(2, "source-b")],
      tenant, now, policy);
    expect(result.sources).toHaveLength(2);
  });
  it("rejects cross-tenant capture inputs", () => {
    expect(() => buildSnapshotTrendReport([capture(1, "source-a", true, "tenant-b")],
      tenant, now, policy)).toThrow(/Cross-organization/);
  });
  it("rejects duplicate timestamps per source", () => {
    expect(() => buildSnapshotTrendReport([capture(1), capture(1)],
      tenant, now, policy)).toThrow(/Duplicate/);
  });
  it("rejects future snapshots", () => {
    const future = { ...capture(1), capturedAt: "2026-11-02T12:00:00.000Z" };
    expect(() => buildSnapshotTrendReport([future], tenant, now, policy))
      .toThrow(/Future/);
  });
  it("limits the number of captures per source", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(2), capture(3)],
      tenant, now, { ...policy, maxCapturesPerSource: 2 });
    expect(result.sources[0]?.captureCount).toBe(2);
  });
  it("reports the largest interval between captures", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(4)],
      tenant, now, policy);
    expect(result.sources[0]?.largestGapDays).toBe(3);
  });
  it("compares the latest two snapshots", () => {
    const result = buildSnapshotTrendReport([capture(1), capture(4)],
      tenant, now, policy);
    expect(result.sources[0]?.latestComparedToPrevious?.newCases).toBe(0);
  });
  it("rejects invalid trend thresholds", () => {
    expect(() => buildSnapshotTrendReport([], tenant, now,
      { ...policy, minimumTrendPoints: 1 })).toThrow(/Invalid/);
  });
  it("rejects a minimum exceeding the capture window", () => {
    expect(() => buildSnapshotTrendReport([], tenant, now,
      { ...policy, maxCapturesPerSource: 1 })).toThrow(/exceed/);
  });
  it("returns empty source list for no snapshots", () => {
    const result = buildSnapshotTrendReport([], tenant, now, policy);
    expect(result.sourceCount).toBe(0);
  });
});
