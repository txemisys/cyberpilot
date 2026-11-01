import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot, SnapshotComparison, CaseDelta } from "./work-integrity-snapshots";
import { caseDimensions, groupCases, caseCohorts, highPriorityCases } from "./work-integrity-analytics";

/** Portable, deterministic exports of case comparisons. Never include credentials. */
export type ReportFormat = "json" | "csv" | "markdown";
export type CaseReportOptions = {
  includeUnchanged?: boolean;
  includeNarrative?: boolean;
  includeCaseDetails?: boolean;
  maxRows?: number;
};
export type CaseReport = {
  schemaVersion: 1;
  organizationId: string;
  capturedBefore: string;
  capturedAfter: string;
  complete: boolean;
  before: ReturnType<typeof caseDimensions>;
  after: ReturnType<typeof caseDimensions>;
  counts: SnapshotComparison["counts"];
  cohorts: ReturnType<typeof caseCohorts>;
  topCases: CaseRow[];
  changes: CaseDelta[];
  limitations: string[];
};
function safeCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  const protectedText = /^[\s\u0000-\u001f]*[=+@\-]/.test(text) ? "'" + text : text;
  return '"' + protectedText.replace(/"/g, '""') + '"';
}
function csvLine(values: readonly unknown[]): string {
  return values.map(safeCell).join(",");
}
export function buildCaseReport(
  before: CaseSnapshot,
  after: CaseSnapshot,
  comparison: SnapshotComparison,
  options: CaseReportOptions = {},
): CaseReport {
  if (before.organizationId !== after.organizationId ||
      comparison.organizationId !== before.organizationId)
    throw new Error("Report scope mismatch.");
  const maxRows = options.maxRows ?? 1000;
  if (!Number.isSafeInteger(maxRows) || maxRows < 0 || maxRows > 10000)
    throw new Error("Invalid report row limit.");
  const changes = comparison.deltas
    .filter(delta => options.includeUnchanged || delta.kind !== "UNCHANGED")
    .slice(0, maxRows);
  return {
    schemaVersion: 1,
    organizationId: comparison.organizationId,
    capturedBefore: comparison.beforeCapturedAt,
    capturedAfter: comparison.afterCapturedAt,
    complete: comparison.complete,
    before: caseDimensions(before.cases),
    after: caseDimensions(after.cases),
    counts: comparison.counts,
    cohorts: caseCohorts(comparison, "code"),
    topCases: options.includeCaseDetails === false ? [] : highPriorityCases(after.cases, Math.min(maxRows, 100)),
    changes,
    limitations: [
      ...comparison.warnings,
      "Snapshot comparisons are not evidence of control effectiveness.",
      "Case-level exports may contain operational identifiers and review rationale; restrict access.",
      ...(!comparison.complete ? ["Missing case records are indeterminate when coverage is incomplete."] : []),
      ...(changes.length < comparison.deltas.filter(x => options.includeUnchanged || x.kind !== "UNCHANGED").length
        ? ["Case change list was truncated by the report row limit."] : []),
    ],
  };
}
export function caseReportCsv(report: CaseReport): string {
  const lines = [
    csvLine(["kind", "key", "workItemId", "resourceId", "code", "beforeState",
      "afterState", "beforeSeverity", "afterSeverity", "beforeRevision", "afterRevision",
      "changedFields", "completeComparison"]),
  ];
  for (const delta of report.changes) {
    lines.push(csvLine([
      delta.kind, delta.key, delta.after?.workItemId ?? delta.before?.workItemId,
      delta.after?.resourceId ?? delta.before?.resourceId,
      delta.after?.code ?? delta.before?.code,
      delta.before?.state, delta.after?.state,
      delta.before?.severity, delta.after?.severity,
      delta.before?.taskRevision, delta.after?.taskRevision,
      delta.changes.join(";"), report.complete,
    ]));
  }
  return lines.join("\r\n") + "\r\n";
}
export function caseReportJson(report: CaseReport): string {
  return JSON.stringify(report, null, 2) + "\n";
}
function escapeMarkdown(value: unknown): string {
  return String(value ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .replace(/[\u0000-\u001f\u007f]/g, " ");
}
export function caseReportMarkdown(report: CaseReport): string {
  const lines = [
    "# Integrity case snapshot comparison",
    "",
    `Organization: ${escapeMarkdown(report.organizationId)}`,
    `Before: ${escapeMarkdown(report.capturedBefore)}`,
    `After: ${escapeMarkdown(report.capturedAfter)}`,
    `Complete comparison: ${report.complete ? "yes" : "no"}`,
    "",
    "## Change summary",
    "",
    "| Change | Cases |",
    "| --- | ---: |",
    ...Object.entries(report.counts).map(([kind, count]) =>
      `| ${escapeMarkdown(kind)} | ${count} |`),
    "",
    "## Case diagnostics",
    "",
    "| Code | Before | After | Entered | Exited |",
    "| --- | ---: | ---: | ---: | ---: |",
    ...report.cohorts.map(cohort =>
      `| ${escapeMarkdown(cohort.cohort)} | ${cohort.before} | ${cohort.after} | ${cohort.entered} | ${cohort.exited} |`),
    "",
    "## Changed cases",
    "",
    "| Change | Work item | Code | Before | After |",
    "| --- | --- | --- | --- | --- |",
    ...report.changes.map(delta =>
      `| ${escapeMarkdown(delta.kind)} | ${escapeMarkdown(delta.after?.workItemId ?? delta.before?.workItemId)} | ${escapeMarkdown(delta.after?.code ?? delta.before?.code)} | ${escapeMarkdown(delta.before?.state)} | ${escapeMarkdown(delta.after?.state)} |`),
    "",
    "## Limitations",
    "",
    ...report.limitations.map(warning => `- ${warning}`),
    "",
  ];
  return lines.join("\n");
}
export function serializeCaseReport(report: CaseReport, format: ReportFormat): string {
  switch (format) {
    case "json": return caseReportJson(report);
    case "csv": return caseReportCsv(report);
    case "markdown": return caseReportMarkdown(report);
  }
}
export type CaseReportDigest = {
  totalBefore: number;
  totalAfter: number;
  criticalBefore: number;
  criticalAfter: number;
  unreviewedBefore: number;
  unreviewedAfter: number;
  changedCases: number;
  indeterminateCases: number;
  complete: boolean;
  topCodes: Array<{ code: string; count: number }>;
};
export function caseReportDigest(report: CaseReport): CaseReportDigest {
  return {
    totalBefore: report.before.total,
    totalAfter: report.after.total,
    criticalBefore: report.before.bySeverity.critical,
    criticalAfter: report.after.bySeverity.critical,
    unreviewedBefore: report.before.unreviewed,
    unreviewedAfter: report.after.unreviewed,
    changedCases: report.counts.CHANGED + report.counts.NEW + report.counts.CLEARED,
    indeterminateCases: report.counts.INDETERMINATE,
    complete: report.complete,
    topCodes: Object.entries(report.after.byCode)
      .map(([code, count]) => ({ code, count }))
      .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code))
      .slice(0, 10),
  };
}
export type CaseRiskBucket = "CRITICAL_UNREVIEWED" | "STALE_REVIEW" |
  "OPEN_INVESTIGATION" | "OTHER_UNREVIEWED" | "REVIEWED" | "HISTORICAL";
export function caseRiskBucket(row: CaseRow): CaseRiskBucket {
  if (row.historicalOnly) return "HISTORICAL";
  if (row.state === "STALE") return "STALE_REVIEW";
  if (row.state === "UNREVIEWED" && row.severity === "critical") return "CRITICAL_UNREVIEWED";
  if (row.state === "INVESTIGATING" || row.state === "REOPENED") return "OPEN_INVESTIGATION";
  if (row.state === "UNREVIEWED") return "OTHER_UNREVIEWED";
  return "REVIEWED";
}
export function riskBucketSummary(rows: readonly CaseRow[]): Record<CaseRiskBucket, number> {
  const result: Record<CaseRiskBucket, number> = {
    CRITICAL_UNREVIEWED: 0, STALE_REVIEW: 0, OPEN_INVESTIGATION: 0,
    OTHER_UNREVIEWED: 0, REVIEWED: 0, HISTORICAL: 0,
  };
  for (const row of rows) result[caseRiskBucket(row)]++;
  return result;
}
export function caseCodeSummary(rows: readonly CaseRow[]) {
  return groupCases(rows, "code").map(group => ({
    code: group.key,
    cases: group.count,
    unreviewed: group.unreviewed,
    stale: group.stale,
    critical: group.critical,
    incompleteCoverage: group.incompleteCoverage,
  }));
}
