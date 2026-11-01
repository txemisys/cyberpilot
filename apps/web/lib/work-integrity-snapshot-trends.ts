import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";
import { compareCaseSnapshots } from "./work-integrity-snapshots";

/**
 * Analyze a rolling window of historical captures per source.
 * This is an operational quality monitor, not a finding verification engine.
 */
export type TrendDirection = "INCREASING" | "DECREASING" | "STABLE" | "INSUFFICIENT";
export type SnapshotTrendMetric =
  | "ACTIVE_CASES" | "CRITICAL_CASES" | "UNREVIEWED_CASES"
  | "QUALITY_BLOCKERS" | "QUALITY_WARNINGS" | "INCOMPLETE_CASES";
export type SnapshotTrendPoint = {
  capturedAt: string;
  source: string;
  complete: boolean;
  activeCases: number;
  criticalCases: number;
  unreviewedCases: number;
  qualityBlockers: number;
  qualityWarnings: number;
  incompleteCases: number;
};
export type SnapshotTrendSeries = {
  source: string;
  metric: SnapshotTrendMetric;
  direction: TrendDirection;
  first: number | null;
  latest: number | null;
  absoluteChange: number | null;
  percentageChange: number | null;
  average: number | null;
  minimum: number | null;
  maximum: number | null;
  points: Array<{ capturedAt: string; value: number }>;
  warnings: string[];
};
export type SnapshotTrendSource = {
  source: string;
  captureCount: number;
  firstCapturedAt: string;
  latestCapturedAt: string;
  completeCaptures: number;
  incompleteCaptures: number;
  largestGapDays: number;
  latestComparedToPrevious: {
    newCases: number;
    clearedCases: number;
    changedCases: number;
    indeterminateCases: number;
  } | null;
  metrics: SnapshotTrendSeries[];
};
export type SnapshotTrendReport = {
  organizationId: string;
  evaluatedAt: string;
  sourceCount: number;
  captureCount: number;
  sources: SnapshotTrendSource[];
  warnings: string[];
};
export type SnapshotTrendPolicy = {
  maxCapturesPerSource: number;
  maxAgeDays: number;
  minimumTrendPoints: number;
  stableAbsoluteThreshold: number;
  requireCompleteForTrend: boolean;
};
const DAY = 86400000;
const metrics: SnapshotTrendMetric[] = [
  "ACTIVE_CASES", "CRITICAL_CASES", "UNREVIEWED_CASES",
  "QUALITY_BLOCKERS", "QUALITY_WARNINGS", "INCOMPLETE_CASES",
];
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function metricValue(point: SnapshotTrendPoint, metric: SnapshotTrendMetric): number {
  switch (metric) {
    case "ACTIVE_CASES": return point.activeCases;
    case "CRITICAL_CASES": return point.criticalCases;
    case "UNREVIEWED_CASES": return point.unreviewedCases;
    case "QUALITY_BLOCKERS": return point.qualityBlockers;
    case "QUALITY_WARNINGS": return point.qualityWarnings;
    case "INCOMPLETE_CASES": return point.incompleteCases;
  }
}
function point(capture: CaseSnapshot): SnapshotTrendPoint {
  const quality = inspectCaptureQuality(capture);
  return {
    source: capture.source, capturedAt: capture.capturedAt, complete: capture.complete,
    activeCases: capture.cases.filter(row => !row.historicalOnly).length,
    criticalCases: capture.cases.filter(row =>
      !row.historicalOnly && row.severity === "critical").length,
    unreviewedCases: capture.cases.filter(row =>
      !row.historicalOnly && row.reviewEventId === null).length,
    qualityBlockers: quality.blockers, qualityWarnings: quality.warnings,
    incompleteCases: capture.cases.filter(row => !row.completeCoverage).length,
  };
}
function series(
  source: string, metric: SnapshotTrendMetric,
  points: SnapshotTrendPoint[], minimum: number, stable: number,
): SnapshotTrendSeries {
  const values = points.map(point => ({
    capturedAt: point.capturedAt, value: metricValue(point, metric),
  }));
  const first = values[0]?.value ?? null;
  const latest = values.at(-1)?.value ?? null;
  const enough = values.length >= minimum;
  const absoluteChange = enough && first !== null && latest !== null ?
    latest - first : null;
  const percentageChange = absoluteChange === null || first === null ||
    first === 0 ? null : Math.round((absoluteChange / first) * 10000) / 100;
  const direction: TrendDirection = absoluteChange === null ? "INSUFFICIENT" :
    Math.abs(absoluteChange) <= stable ? "STABLE" :
    absoluteChange > 0 ? "INCREASING" : "DECREASING";
  const average = values.length ?
    Math.round(values.reduce((sum, item) => sum + item.value, 0) / values.length * 100) / 100 : null;
  return {
    source, metric, direction, first, latest, absoluteChange, percentageChange,
    average, minimum: values.length ? Math.min(...values.map(v => v.value)) : null,
    maximum: values.length ? Math.max(...values.map(v => v.value)) : null,
    points: values,
    warnings: [
      ...(!enough ? ["Insufficient comparable capture points for a directional trend."] : []),
      ...(first === 0 && absoluteChange !== null ?
        ["Percentage change is undefined when the initial count is zero."] : []),
      "Counts reflect recorded diagnostics, not independently verified control outcomes.",
    ],
  };
}
export function buildSnapshotTrendReport(
  input: readonly unknown[], organizationId: string, evaluatedAt: string,
  policy: SnapshotTrendPolicy,
): SnapshotTrendReport {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  if (input.length > 10000) throw new Error("Trend capture limit exceeded.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid trend evaluation time.");
  const maxCapturesPerSource = integer(policy.maxCapturesPerSource, 1, 1000, "capture window");
  const maxAgeDays = integer(policy.maxAgeDays, 1, 3650, "age window");
  const minimumTrendPoints = integer(policy.minimumTrendPoints, 2, 1000, "trend points");
  const stableAbsoluteThreshold = integer(policy.stableAbsoluteThreshold, 0, 10000,
    "stability threshold");
  if (minimumTrendPoints > maxCapturesPerSource)
    throw new Error("Trend points exceed the capture window.");
  const groups = new Map<string, CaseSnapshot[]>();
  const identities = new Set<string>();
  for (const raw of input) {
    const capture = parseCaseSnapshot(raw);
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization trend capture is forbidden.");
    const time = Date.parse(capture.capturedAt);
    if (time > now) throw new Error("Future captures are forbidden in historical trends.");
    const key = JSON.stringify([capture.source, time]);
    if (identities.has(key)) throw new Error("Duplicate trend capture identity.");
    identities.add(key);
    if (now - time > maxAgeDays * DAY) continue;
    const group = groups.get(capture.source) ?? [];
    group.push(capture);
    groups.set(capture.source, group);
  }
  const sources: SnapshotTrendSource[] = [];
  for (const [source, group] of groups) {
    const captures = group.sort((a, b) =>
      Date.parse(a.capturedAt) - Date.parse(b.capturedAt))
      .slice(-maxCapturesPerSource);
    const allPoints = captures.map(point);
    const selected = policy.requireCompleteForTrend ?
      allPoints.filter(point => point.complete) : allPoints;
    const gapDays = captures.slice(1).map((capture, index) =>
      (Date.parse(capture.capturedAt) -
        Date.parse(captures[index]!.capturedAt)) / DAY);
    const latest = captures.at(-1)!;
    const previous = captures.at(-2);
    const comparison = previous ? compareCaseSnapshots(previous, latest) : null;
    sources.push({
      source, captureCount: captures.length,
      firstCapturedAt: captures[0]!.capturedAt,
      latestCapturedAt: latest.capturedAt,
      completeCaptures: captures.filter(capture => capture.complete).length,
      incompleteCaptures: captures.filter(capture => !capture.complete).length,
      largestGapDays: gapDays.length ? Math.max(...gapDays) : 0,
      latestComparedToPrevious: comparison ? {
        newCases: comparison.counts.NEW, clearedCases: comparison.counts.CLEARED,
        changedCases: comparison.counts.CHANGED,
        indeterminateCases: comparison.counts.INDETERMINATE,
      } : null,
      metrics: metrics.map(metric =>
        series(source, metric, selected, minimumTrendPoints, stableAbsoluteThreshold)),
    });
  }
  sources.sort((a, b) => a.source.localeCompare(b.source));
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    sourceCount: sources.length,
    captureCount: sources.reduce((sum, source) => sum + source.captureCount, 0),
    sources,
    warnings: [
      "Historical trend series use caller-supplied snapshots and cannot authenticate provenance.",
      "Incomplete captures can produce misleading changes in observed diagnostic counts.",
      "A decrease in recorded cases is not independent evidence of successful remediation.",
    ],
  };
}
