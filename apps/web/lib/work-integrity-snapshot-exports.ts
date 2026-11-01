import type { ContinuityReport } from "./work-integrity-case-continuity";
import type { SnapshotTrendReport } from "./work-integrity-snapshot-trends";
import type { SnapshotIncidentReport } from "./work-integrity-snapshot-incidents";
import type { SnapshotReleaseBatch } from "./work-integrity-snapshot-release";
import type { SnapshotCatalog } from "./work-integrity-snapshot-catalog";

/**
 * Spreadsheet-safe exports. Every untrusted field is quoted and formula
 * prefixes are neutralized before emitting UTF-8 CSV.
 */
function cell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return "";
  const raw = String(value);
  const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
  return '"' + neutralized.replace(/"/g, '""') + '"';
}
function row(values: Array<string | number | boolean | null | undefined>): string {
  return values.map(cell).join(",");
}
function document(header: string[], records: Array<Array<string | number | boolean | null | undefined>>): string {
  return "\uFEFF" + [row(header), ...records.map(row)].join("\r\n") + "\r\n";
}
export function snapshotCatalogCsv(report: SnapshotCatalog): string {
  return document([
    "organizationId", "source", "capturedAt", "complete", "safeToTreatAsComplete",
    "cases", "blockers", "warnings", "activeCases", "reviewedCases",
    "criticalCases", "distinctWorkItems",
  ], report.entries.map(item => [
    report.organizationId, item.source, item.capturedAt, item.complete,
    item.safeToTreatAsComplete, item.cases, item.blockers, item.warnings,
    item.activeCases, item.reviewedCases, item.criticalCases, item.distinctWorkItems,
  ]));
}
export function snapshotTrendCsv(report: SnapshotTrendReport): string {
  const records: Array<Array<string | number | boolean | null | undefined>> = [];
  for (const source of report.sources) {
    for (const metric of source.metrics) {
      for (const point of metric.points) {
        records.push([
          report.organizationId, source.source, metric.metric,
          point.capturedAt, point.value, metric.direction,
          metric.first, metric.latest, metric.absoluteChange,
          metric.percentageChange, metric.average,
        ]);
      }
    }
  }
  return document([
    "organizationId", "source", "metric", "capturedAt", "value",
    "direction", "first", "latest", "absoluteChange", "percentageChange", "average",
  ], records);
}
export function snapshotIncidentCsv(report: SnapshotIncidentReport): string {
  return document([
    "organizationId", "source", "kind", "severity", "baselineAt",
    "currentAt", "baselineValue", "currentValue", "affectedCaseKeys",
    "explanation", "nextAction",
  ], report.incidents.map(item => [
    report.organizationId, item.source, item.kind, item.severity,
    item.baselineAt, item.currentAt, item.baselineValue, item.currentValue,
    item.affectedCaseKeys.join(";"), item.explanation, item.nextAction,
  ]));
}
export function snapshotReleaseCsv(report: SnapshotReleaseBatch): string {
  const records: Array<Array<string | number | boolean | null | undefined>> = [];
  for (const result of report.results) {
    for (const gate of result.gates) {
      records.push([
        report.organizationId, result.source, result.capturedAt,
        result.evaluatedAt, result.eligible, gate.gate, gate.passed,
        gate.explanation, gate.requiredAction, result.manifestDigest,
      ]);
    }
  }
  return document([
    "organizationId", "source", "capturedAt", "evaluatedAt", "eligible",
    "gate", "passed", "explanation", "requiredAction", "manifestDigest",
  ], records);
}
export function caseContinuityCsv(report: ContinuityReport): string {
  const records: Array<Array<string | number | boolean | null | undefined>> = [];
  for (const source of report.sources) {
    for (const item of source.cases) {
      for (const event of item.events) {
        records.push([
          report.organizationId, source.source, item.caseKey,
          item.firstSeenAt, item.lastSeenAt, item.latestState,
          item.observedCaptures, item.missingCaptures,
          item.uncertainCaptures, item.returnCount, item.changeCount,
          event.capturedAt, event.state, event.previousCapturedAt,
          event.changedFields.join(";"), event.evidenceComplete,
        ]);
      }
    }
  }
  return document([
    "organizationId", "source", "caseKey", "firstSeenAt", "lastSeenAt",
    "latestState", "observedCaptures", "missingCaptures", "uncertainCaptures",
    "returnCount", "changeCount", "eventAt", "eventState",
    "previousCapturedAt", "changedFields", "evidenceComplete",
  ], records);
}
export type SnapshotCsvKind =
  | "catalog" | "trends" | "incidents" | "release-batch" | "continuity";
export function exportSnapshotReport(kind: SnapshotCsvKind, report: unknown): string {
  switch (kind) {
    case "catalog": return snapshotCatalogCsv(report as SnapshotCatalog);
    case "trends": return snapshotTrendCsv(report as SnapshotTrendReport);
    case "incidents": return snapshotIncidentCsv(report as SnapshotIncidentReport);
    case "release-batch": return snapshotReleaseCsv(report as SnapshotReleaseBatch);
    case "continuity": return caseContinuityCsv(report as ContinuityReport);
  }
}
