import type { IntegrityCode, IntegrityFinding, IntegritySeverity } from "./work-integrity";

/**
 * Portable operational review package. Explicitly distinct from security attestation.
 * Each row records the diagnostic's limited coverage and human follow-up.
 */
export type IntegrityDisposition =
  | "unreviewed" | "needs-investigation" | "accepted-exception" | "resolved-in-records";
export type IntegrityReviewRow = {
  workItemId: string;
  resourceId: string;
  code: IntegrityCode;
  severity: IntegritySeverity;
  message: string;
  recommendation: string;
  taskStatus: string;
  taskRevision: number;
  taskUpdatedAt: string;
  coverageComplete: boolean;
  disposition: IntegrityDisposition;
  reviewerNote: string;
};
export type IntegrityExportSource = {
  generatedAt: string;
  organizationId: string;
  checked: number;
  nextCursor: string | null;
  items: Array<{
    workItemId: string;
    status: string;
    revision: number;
    updatedAt: Date | string;
    complete: boolean;
    findings: IntegrityFinding[];
  }>;
  limitations: string[];
};
export const INTEGRITY_DISPOSITIONS: readonly IntegrityDisposition[] = [
  "unreviewed", "needs-investigation", "accepted-exception", "resolved-in-records",
];
export type IntegrityExportOptions = {
  includeEmpty: boolean;
  severity: "all" | IntegritySeverity;
  codes: ReadonlySet<IntegrityCode> | null;
  includeExplanation: boolean;
};
export const defaultIntegrityExportOptions: IntegrityExportOptions = {
  includeEmpty: false,
  severity: "all",
  codes: null,
  includeExplanation: true,
};
export function selectIntegrityRows(
  source: IntegrityExportSource,
  options: IntegrityExportOptions = defaultIntegrityExportOptions,
): IntegrityReviewRow[] {
  const rows: IntegrityReviewRow[] = [];
  for (const item of source.items) {
    const updatedAt = item.updatedAt instanceof Date
      ? item.updatedAt.toISOString() : item.updatedAt;
    const matching = item.findings.filter(finding =>
      (options.severity === "all" || options.severity === finding.severity) &&
      (!options.codes || options.codes.has(finding.code)),
    );
    for (const finding of matching) {
      rows.push({
        workItemId: item.workItemId,
        resourceId: finding.resourceId,
        code: finding.code,
        severity: finding.severity,
        message: finding.message,
        recommendation: finding.recommendation,
        taskStatus: item.status,
        taskRevision: item.revision,
        taskUpdatedAt: updatedAt,
        coverageComplete: item.complete,
        disposition: "unreviewed",
        reviewerNote: "",
      });
    }
    if (options.includeEmpty && matching.length === 0) {
      // Empty rows express only "no signals returned", never verified security.
      rows.push({
        workItemId: item.workItemId,
        resourceId: item.workItemId,
        code: "" as IntegrityCode,
        severity: "info",
        message: item.complete
          ? "No matching diagnostic signals on this page."
          : "No matching signals; some linked collections were truncated.",
        recommendation: "Do not treat diagnostic silence as compliance or verification.",
        taskStatus: item.status,
        taskRevision: item.revision,
        taskUpdatedAt: updatedAt,
        coverageComplete: item.complete,
        disposition: "unreviewed",
        reviewerNote: "",
      });
    }
  }
  return rows;
}
export type IntegrityExportMetadata = {
  kind: "CYBERPILOT_OPERATIONAL_INTEGRITY_REVIEW";
  schemaVersion: 1;
  generatedAt: string;
  organizationId: string;
  recordsExamined: number;
  findingsExported: number;
  sourceHasMorePages: boolean;
  recordsWithPartialCoverage: number;
  limitations: string[];
  disclaimer: string;
};
export function integrityExportMetadata(
  source: IntegrityExportSource,
  rows: readonly IntegrityReviewRow[],
): IntegrityExportMetadata {
  return {
    kind: "CYBERPILOT_OPERATIONAL_INTEGRITY_REVIEW",
    schemaVersion: 1,
    generatedAt: source.generatedAt,
    organizationId: source.organizationId,
    recordsExamined: source.checked,
    findingsExported: rows.filter(row => row.code !== "").length,
    sourceHasMorePages: source.nextCursor !== null,
    recordsWithPartialCoverage: source.items.filter(item => !item.complete).length,
    limitations: [...source.limitations],
    disclaimer: "Read-only data quality review; not an assurance, certification, refreshed evidence, or finding closure.",
  };
}
export const INTEGRITY_CSV_FIELDS = [
  "Work item ID",
  "Linked resource ID",
  "Diagnostic code",
  "Diagnostic severity",
  "Diagnostic message",
  "Recommended follow-up",
  "Task status",
  "Task revision",
  "Task updated at UTC",
  "Linked records complete",
  "Review disposition",
  "Reviewer note",
] as const;
function neutralizeSpreadsheetFormula(value: string): string {
  // Excel and other spreadsheet tools interpret formula prefixes after whitespace.
  // Prefixing with an apostrophe forces literal interpretation.
  if (/^[\s\u0000-\u001f]*[=+@-]/.test(value)) return "'" + value;
  return value;
}
export function csvField(value: string | number | boolean | null): string {
  const safe = neutralizeSpreadsheetFormula(value === null ? "" : String(value));
  return '"' + safe.replace(/"/g, '""') + '"';
}
export function csvLine(values: readonly (string | number | boolean | null)[]): string {
  return values.map(csvField).join(",");
}
export function workIntegrityCsv(
  source: IntegrityExportSource,
  rows: readonly IntegrityReviewRow[],
  includeExplanation = true,
): string {
  const metadata = integrityExportMetadata(source, rows);
  const lines: string[] = [];
  if (includeExplanation) {
    lines.push(csvLine(["Export type", metadata.kind]));
    lines.push(csvLine(["Schema version", metadata.schemaVersion]));
    lines.push(csvLine(["Organization scope", metadata.organizationId]));
    lines.push(csvLine(["Generated UTC", metadata.generatedAt]));
    lines.push(csvLine(["Records examined in page", metadata.recordsExamined]));
    lines.push(csvLine(["Diagnostic findings exported", metadata.findingsExported]));
    lines.push(csvLine(["More pages available", metadata.sourceHasMorePages]));
    lines.push(csvLine(["Incomplete linked-record coverage", metadata.recordsWithPartialCoverage]));
    lines.push(csvLine(["Disclaimer", metadata.disclaimer]));
    for (const limitation of metadata.limitations) {
      lines.push(csvLine(["Limitation", limitation]));
    }
    lines.push("");
  }
  lines.push(csvLine(INTEGRITY_CSV_FIELDS));
  for (const row of rows) {
    lines.push(csvLine([
      row.workItemId, row.resourceId, row.code, row.severity,
      row.message, row.recommendation, row.taskStatus,
      row.taskRevision, row.taskUpdatedAt, row.coverageComplete,
      row.disposition, row.reviewerNote,
    ]));
  }
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}
export function workIntegrityJson(
  source: IntegrityExportSource,
  rows: readonly IntegrityReviewRow[],
): string {
  return JSON.stringify({
    metadata: integrityExportMetadata(source, rows),
    records: rows,
  }, null, 2);
}
export type IntegrityReviewStatistics = {
  examined: number;
  withFindings: number;
  withoutFindings: number;
  partialCoverage: number;
  critical: number;
  attention: number;
  informational: number;
  byCode: Array<{ code: string; count: number }>;
  byStatus: Array<{ status: string; checked: number; flagged: number }>;
};
export function summarizeIntegrityReview(source: IntegrityExportSource): IntegrityReviewStatistics {
  const totals = new Map<string, number>();
  const statuses = new Map<string, { status: string; checked: number; flagged: number }>();
  const result: IntegrityReviewStatistics = {
    examined: source.items.length,
    withFindings: 0,
    withoutFindings: 0,
    partialCoverage: 0,
    critical: 0,
    attention: 0,
    informational: 0,
    byCode: [],
    byStatus: [],
  };
  for (const item of source.items) {
    if (!item.complete) result.partialCoverage++;
    if (item.findings.length > 0) result.withFindings++;
    else result.withoutFindings++;
    const status = statuses.get(item.status) ?? { status: item.status, checked: 0, flagged: 0 };
    status.checked++;
    if (item.findings.length) status.flagged++;
    statuses.set(item.status, status);
    for (const finding of item.findings) {
      if (finding.severity === "critical") result.critical++;
      else if (finding.severity === "attention") result.attention++;
      else result.informational++;
      totals.set(finding.code, (totals.get(finding.code) ?? 0) + 1);
    }
  }
  result.byCode = [...totals].map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
  result.byStatus = [...statuses.values()].sort((a, b) => a.status.localeCompare(b.status));
  return result;
}
export type IntegrityTriageGroup = {
  title: string;
  priority: number;
  affectedWorkItems: string[];
  findingCount: number;
  codes: string[];
  nextAction: string;
  verificationCaveat: string;
};
export function buildIntegrityTriage(rows: readonly IntegrityReviewRow[]): IntegrityTriageGroup[] {
  const buckets = [
    {
      title: "Tenant and relationship integrity", priority: 1,
      codes: ["FINDING_MISMATCH", "EVIDENCE_ORGANIZATION_MISMATCH", "EVIDENCE_LINK_MISSING_TARGET"],
      nextAction: "Restrict affected data access and investigate foreign keys, migration history and tenant boundaries before editing the records.",
    },
    {
      title: "Event and revision integrity", priority: 2,
      codes: ["EVENT_REVISION_AHEAD", "EVENT_TIME_ORDER", "EVENT_SNAPSHOT_MISMATCH", "INVALID_EVENT_SNAPSHOT", "MISSING_CREATE_EVENT"],
      nextAction: "Compare immutable event history against stored revisions and identify the first divergent mutation.",
    },
    {
      title: "Responsibility and handoffs", priority: 3,
      codes: ["ASSIGNEE_NOT_MEMBER", "HANDOFF_RECIPIENT_NOT_MEMBER", "HANDOFF_DECISION_INCOMPLETE", "HANDOFF_UNDECIDED_WITH_DECISION", "HANDOFF_EXPIRED_PENDING", "HANDOFF_ASSIGNEE_DIVERGENCE"],
      nextAction: "Ask an organization owner or admin to review membership and assignment decisions.",
    },
    {
      title: "Completion and checklist attribution", priority: 4,
      codes: ["DONE_WITHOUT_COMPLETION", "OPEN_WITH_COMPLETION", "COMPLETION_BEFORE_CREATION", "CHECKLIST_COMPLETER_MISMATCH", "CHECKLIST_COMPLETED_WITHOUT_ACTOR", "CHECKLIST_ACTOR_WITHOUT_COMPLETION"],
      nextAction: "Review recorded status transitions and checklist attribution; do not mark controls verified.",
    },
    {
      title: "Dates and evidence unlink history", priority: 5,
      codes: ["DEADLINE_BEFORE_CREATION", "EVENT_AFTER_LAST_UPDATE", "EVIDENCE_UNLINKED_WITHOUT_ACTOR", "EVIDENCE_UNLINK_ACTOR_WITHOUT_DATE"],
      nextAction: "Reconcile timestamps and audit the actor attribution against the original activity records.",
    },
  ];
  return buckets.flatMap(bucket => {
    const selected = rows.filter(row => bucket.codes.includes(row.code));
    if (!selected.length) return [];
    return [{
      title: bucket.title,
      priority: bucket.priority,
      affectedWorkItems: [...new Set(selected.map(row => row.workItemId))].sort(),
      findingCount: selected.length,
      codes: [...new Set(selected.map(row => row.code))].sort(),
      nextAction: bucket.nextAction,
      verificationCaveat: "This group describes data anomalies, not proven exploitation or compliance status.",
    }];
  });
}
