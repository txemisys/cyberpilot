import type { AuditDigest, AuditDigestBucket, AuditDigestCase } from "./work-integrity-audit-digest";

/**
 * Internal arithmetic reconciliation for independently sourced audit summaries.
 * A consistent summary is not an attestation that audit events cannot be altered.
 */
export type AuditReconciliationCode =
  | "DAILY_TOTAL_MISMATCH"
  | "DECISION_TOTAL_MISMATCH"
  | "CASE_COUNT_MISMATCH"
  | "WORK_COUNT_MISMATCH"
  | "ACTOR_COUNT_MISMATCH"
  | "UNKNOWN_ACTOR_MISMATCH"
  | "OUTDATED_COUNT_MISMATCH"
  | "MALFORMED_COUNT_MISMATCH"
  | "SOURCE_ROW_ACCOUNTING_MISMATCH"
  | "INVALID_DAILY_METRIC"
  | "INVALID_CASE_METRIC"
  | "INVALID_ACTOR_METRIC"
  | "DUPLICATE_CASE_IDENTITY"
  | "DUPLICATE_ACTOR_IDENTITY"
  | "DUPLICATE_DAY"
  | "INVALID_DATE_ORDER"
  | "CASE_REVISION_INCONSISTENCY"
  | "COVERAGE_FLAG_INCONSISTENCY";
export type AuditReconciliationIssue = {
  code: AuditReconciliationCode;
  severity: "ERROR" | "WARNING" | "UNKNOWN";
  scope: "DIGEST" | "DAY" | "CASE" | "ACTOR";
  identity: string | null;
  expected: number | string | null;
  actual: number | string | null;
  explanation: string;
  recommendedAction: string;
};
export type AuditReconciliationReport = {
  organizationId: string;
  from: string;
  to: string;
  internallyConsistent: boolean;
  sourceIsComplete: boolean;
  errors: number;
  warnings: number;
  unknowns: number;
  reviewedDays: number;
  reviewedCases: number;
  reviewedActors: number;
  issues: AuditReconciliationIssue[];
  limitations: string[];
};
const total = (numbers: readonly number[]) => numbers.reduce((sum, n) => sum + n, 0);
function integer(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}
function verifyDay(day: AuditDigestBucket, emit: (
  code: AuditReconciliationCode, scope: AuditReconciliationIssue["scope"],
  identity: string | null, expected: number | string | null,
  actual: number | string | null, explanation: string,
) => void): void {
  const values = [
    day.recorded, day.investigations, day.acknowledgements, day.dismissals,
    day.reopenings, day.uniqueCases, day.uniqueWorkItems, day.actors,
    day.unknownActors, day.staleReviews, day.malformed,
  ];
  if (values.some(value => !integer(value))) emit(
    "INVALID_DAILY_METRIC", "DAY", day.day, null, null,
    "A daily audit metric is negative, fractional or otherwise invalid.");
  const subtotal = total([
    day.investigations, day.acknowledgements, day.dismissals, day.reopenings,
  ]);
  if (day.recorded !== subtotal) emit(
    "DAILY_TOTAL_MISMATCH", "DAY", day.day, subtotal, day.recorded,
    "The daily recorded decisions do not equal their decision categories.");
  if (day.uniqueCases > day.recorded || day.uniqueWorkItems > day.recorded ||
      day.actors > day.recorded || day.unknownActors > day.recorded ||
      day.staleReviews > day.recorded) emit(
    "INVALID_DAILY_METRIC", "DAY", day.day, day.recorded, null,
    "A daily subset count exceeds all decoded decisions.");
}
function verifyCase(row: AuditDigestCase, emit: (
  code: AuditReconciliationCode, scope: AuditReconciliationIssue["scope"],
  identity: string | null, expected: number | string | null,
  actual: number | string | null, explanation: string,
) => void): void {
  if (!integer(row.events) || row.events === 0 ||
      !integer(row.latestReviewedRevision) || row.latestReviewedRevision < 1) emit(
    "INVALID_CASE_METRIC", "CASE", row.caseKey, null, row.events,
    "A case has no valid recorded decisions or last review revision.");
  if (row.currentWorkRevision === null && row.currentlyReviewed !== null) emit(
    "CASE_REVISION_INCONSISTENCY", "CASE", row.caseKey, null,
    String(row.currentlyReviewed), "Current review status was claimed for unavailable work.");
  if (row.currentWorkRevision !== null &&
      row.currentlyReviewed !== (row.currentWorkRevision === row.latestReviewedRevision)) emit(
    "CASE_REVISION_INCONSISTENCY", "CASE", row.caseKey,
    String(row.currentWorkRevision === row.latestReviewedRevision),
    String(row.currentlyReviewed),
    "The current review flag disagrees with stored work and review revisions.");
}
export function reconcileAuditDigest(digest: AuditDigest): AuditReconciliationReport {
  if (!digest.organizationId) throw new Error("Trusted organization required.");
  const issues: AuditReconciliationIssue[] = [];
  const emit = (
    code: AuditReconciliationCode, scope: AuditReconciliationIssue["scope"],
    identity: string | null, expected: number | string | null,
    actual: number | string | null, explanation: string,
    severity: AuditReconciliationIssue["severity"] = "ERROR",
  ) => issues.push({
    code, severity, scope, identity, expected, actual, explanation,
    recommendedAction: severity === "UNKNOWN"
      ? "Inspect the bounded event coverage before treating the figure as authoritative."
      : "Re-read the tenant-scoped source events and reconstruct the affected summary.",
  });
  const from = Date.parse(digest.from);
  const to = Date.parse(digest.to);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) emit(
    "INVALID_DATE_ORDER", "DIGEST", null, digest.from, digest.to,
    "The reported audit period is reversed or malformed.");
  const days = new Set<string>();
  for (const day of digest.daily) {
    if (days.has(day.day)) emit(
      "DUPLICATE_DAY", "DAY", day.day, 1, 2,
      "The source digest contains multiple buckets for one calendar day.");
    days.add(day.day);
    verifyDay(day, emit);
  }
  const caseIds = new Set<string>();
  for (const row of digest.cases) {
    if (caseIds.has(row.caseKey)) emit(
      "DUPLICATE_CASE_IDENTITY", "CASE", row.caseKey, 1, 2,
      "The same diagnostic identity occurs more than once in the case rollup.");
    caseIds.add(row.caseKey);
    verifyCase(row, emit);
  }
  const actors = new Set<string>();
  for (const actor of digest.actors) {
    const identity = actor.actorUserId ?? "__missing__";
    if (actors.has(identity)) emit(
      "DUPLICATE_ACTOR_IDENTITY", "ACTOR", identity, 1, 2,
      "The actor rollup has a duplicated identity.");
    actors.add(identity);
    if (!integer(actor.recorded) || actor.recorded < 1 ||
        !integer(actor.workItems) || actor.workItems > actor.recorded ||
        Object.values(actor.decisions).some(value => !integer(value)) ||
        total(Object.values(actor.decisions)) !== actor.recorded) emit(
      "INVALID_ACTOR_METRIC", "ACTOR", identity, actor.recorded,
      total(Object.values(actor.decisions)),
      "The actor decision breakdown disagrees with its recorded total.");
  }
  const check = (
    code: AuditReconciliationCode,
    expected: number, actual: number, explanation: string,
  ) => {
    if (expected !== actual) emit(code, "DIGEST", null, expected, actual, explanation);
  };
  check("DAILY_TOTAL_MISMATCH",
    total(digest.daily.map(day => day.recorded)),
    digest.recorded, "Overall decision total differs from daily totals.");
  check("DECISION_TOTAL_MISMATCH",
    total(Object.values(digest.decisions)),
    digest.recorded, "Overall decision total differs from its decision breakdown.");
  check("CASE_COUNT_MISMATCH", caseIds.size, digest.uniqueCases,
    "Unique case count disagrees with the case rollup.");
  check("WORK_COUNT_MISMATCH", new Set(digest.cases.map(row => row.workItemId)).size,
    digest.uniqueWorkItems, "Distinct work count disagrees with case rollup.");
  check("ACTOR_COUNT_MISMATCH", digest.actors.length, digest.reviewedByActors,
    "Actor identity count disagrees with actor rollup.");
  check("ACTOR_COUNT_MISMATCH",
    digest.actors.filter(actor => actor.actorUserId !== null).length,
    digest.knownActorCount, "Known reviewer identities disagree with the actor rollup.");
  check("UNKNOWN_ACTOR_MISMATCH", total(digest.daily.map(day => day.unknownActors)),
    digest.unattributedDecisionCount, "Unattributed event total differs from day buckets.");
  check("OUTDATED_COUNT_MISMATCH", total(digest.daily.map(day => day.staleReviews)),
    digest.outdatedReviewCount, "Outdated review total differs from day buckets.");
  check("MALFORMED_COUNT_MISMATCH", total(digest.daily.map(day => day.malformed)),
    digest.malformed, "Malformed row total differs from source day buckets.");
  const accounted = digest.recorded + digest.malformed;
  if (accounted !== digest.rawRecordsRead) emit(
    "SOURCE_ROW_ACCOUNTING_MISMATCH", "DIGEST", null,
    accounted, digest.rawRecordsRead,
    "Recorded decisions plus malformed rows do not account for the raw source page.",
    digest.historyTruncated ? "UNKNOWN" : "WARNING",
  );
  if (digest.historyTruncated && digest.historyCoverage !== "TRUNCATED") emit(
    "COVERAGE_FLAG_INCONSISTENCY", "DIGEST", null,
    "TRUNCATED", digest.historyCoverage,
    "The source cap was reached, but the digest claims another coverage status.");
  if (!digest.historyTruncated && digest.malformed > 0 &&
      digest.historyCoverage !== "MALFORMED") emit(
    "COVERAGE_FLAG_INCONSISTENCY", "DIGEST", null,
    "MALFORMED", digest.historyCoverage,
    "Malformed source records were observed but not reflected in coverage.");
  const errors = issues.filter(issue => issue.severity === "ERROR").length;
  const warnings = issues.filter(issue => issue.severity === "WARNING").length;
  const unknowns = issues.filter(issue => issue.severity === "UNKNOWN").length;
  return {
    organizationId: digest.organizationId, from: digest.from, to: digest.to,
    internallyConsistent: errors === 0 && warnings === 0 && unknowns === 0,
    sourceIsComplete: !digest.historyTruncated && digest.malformed === 0,
    errors, warnings, unknowns,
    reviewedDays: digest.daily.length, reviewedCases: digest.cases.length,
    reviewedActors: digest.actors.length, issues,
    limitations: [
      "This reconciles only internal sums and identities in the source-derived report.",
      "Even an arithmetically consistent digest is not proof of an immutable audit source.",
      "A valid human review history does not establish that security findings were resolved.",
      "The underlying source may be bounded by a record cap or historical work revisions.",
    ],
  };
}
export function auditReconciliationCsv(report: AuditReconciliationReport): string {
  const quote = (value: unknown) => {
    const text = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(text) ? "'" + text : text;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const cols = ["code", "severity", "scope", "identity", "expected", "actual",
    "explanation", "recommendedAction"];
  const rows = [cols.map(quote).join(",")];
  for (const issue of report.issues) rows.push([
    issue.code, issue.severity, issue.scope, issue.identity,
    issue.expected, issue.actual, issue.explanation, issue.recommendedAction,
  ].map(quote).join(","));
  return rows.join("\r\n") + "\r\n";
}
