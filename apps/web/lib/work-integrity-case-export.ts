import {
  type CasePage, type CaseRow, type CaseState, CASE_STATES,
} from "./work-integrity-cases";

/**
 * Portable case export, deliberately scoped to exactly one bounded page.
 * This produces a task coordination record, not an assurance report.
 */
export const CASE_CSV_COLUMNS = [
  "Work item ID",
  "Diagnostic code",
  "Linked resource",
  "Current task status",
  "Current task revision",
  "Diagnostic severity",
  "Diagnostic description",
  "Suggested follow-up",
  "Review state",
  "Latest audit event ID",
  "Latest review time UTC",
  "Review revision",
  "Review actor ID",
  "Review rationale",
  "Review reference",
  "Linked record coverage complete",
  "Historical-only diagnostic",
] as const;
export type CaseExport = {
  schemaVersion: 1;
  kind: "CYBERPILOT_OPERATIONAL_INTEGRITY_CASES";
  organizationNotice: string;
  generatedAt: string;
  examinedWorkItems: number;
  exportedCases: number;
  nextCursor: string | null;
  completeAuditHistory: boolean;
  limitations: string[];
  cases: CaseRow[];
};
export function caseExportPayload(page: CasePage): CaseExport {
  return {
    schemaVersion: 1,
    kind: "CYBERPILOT_OPERATIONAL_INTEGRITY_CASES",
    organizationNotice: "Only cases from the authenticated tenant and selected work-item page are included.",
    generatedAt: page.generatedAt,
    examinedWorkItems: page.totalWorkItemsExamined,
    exportedCases: page.cases.length,
    nextCursor: page.nextCursor,
    completeAuditHistory: page.historyComplete,
    limitations: [...page.limitations],
    cases: page.cases.map(item => ({ ...item })),
  };
}
export function serializeCaseJson(page: CasePage): string {
  return JSON.stringify(caseExportPayload(page), null, 2);
}
function neutralize(value: string): string {
  return /^[\u0000-\u0020]*[=+@-]/.test(value) ? "'" + value : value;
}
export function safeCaseCell(value: unknown): string {
  const literal = value === null || value === undefined ? "" : String(value);
  return '"' + neutralize(literal).replace(/"/g, '""') + '"';
}
export function safeCaseRow(values: readonly unknown[]): string {
  return values.map(safeCaseCell).join(",");
}
export function serializeCaseCsv(page: CasePage): string {
  const metadata = caseExportPayload(page);
  const lines = [
    safeCaseRow(["Export type", metadata.kind]),
    safeCaseRow(["Schema version", metadata.schemaVersion]),
    safeCaseRow(["Scope", metadata.organizationNotice]),
    safeCaseRow(["Generated UTC", metadata.generatedAt]),
    safeCaseRow(["Work items examined in page", metadata.examinedWorkItems]),
    safeCaseRow(["Cases exported", metadata.exportedCases]),
    safeCaseRow(["Next page cursor", metadata.nextCursor]),
    safeCaseRow(["Audit history complete", metadata.completeAuditHistory]),
    safeCaseRow(["Disclaimer", "Diagnostic review is not security verification or compliance certification."]),
    ...metadata.limitations.map(text => safeCaseRow(["Limitation", text])),
    "",
    safeCaseRow(CASE_CSV_COLUMNS),
  ];
  for (const item of page.cases) {
    lines.push(safeCaseRow([
      item.workItemId, item.code, item.resourceId,
      item.taskStatus, item.taskRevision, item.severity,
      item.diagnostic, item.recommendation, item.state,
      item.reviewEventId, item.reviewedAt, item.reviewedRevision,
      item.reviewerUserId, item.reviewRationale, item.reviewReference,
      item.completeCoverage, item.historicalOnly,
    ]));
  }
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}
export type CaseReviewAction = {
  state: CaseState;
  label: string;
  followUp: string;
  requiresFreshAssessment: boolean;
  canTreatAsReviewed: boolean;
};
export function explainCaseState(state: CaseState): CaseReviewAction {
  switch (state) {
    case "UNREVIEWED":
      return { state, label: "Not yet reviewed",
        followUp: "Assign an authorized reviewer to examine the underlying records.",
        requiresFreshAssessment: true, canTreatAsReviewed: false };
    case "INVESTIGATING":
      return { state, label: "Investigation in progress",
        followUp: "Gather referenced records and record an explicit reason for the next decision.",
        requiresFreshAssessment: false, canTreatAsReviewed: true };
    case "ACKNOWLEDGED":
      return { state, label: "Acknowledged discrepancy",
        followUp: "Track any remediation separately; acknowledgement alone does not fix the record.",
        requiresFreshAssessment: false, canTreatAsReviewed: true };
    case "DISMISSED":
      return { state, label: "Dismissed with justification",
        followUp: "Retain rationale and re-open if evidence or task revision changes.",
        requiresFreshAssessment: false, canTreatAsReviewed: true };
    case "REOPENED":
      return { state, label: "Reopened for investigation",
        followUp: "Re-evaluate the discrepancy before a new determination.",
        requiresFreshAssessment: true, canTreatAsReviewed: true };
    case "STALE":
      return { state, label: "Decision based on an outdated revision",
        followUp: "Inspect the current task state and record a new review tied to that revision.",
        requiresFreshAssessment: true, canTreatAsReviewed: false };
    case "NO_LONGER_DETECTED":
      return { state, label: "Historical diagnostic not currently detected",
        followUp: "Confirm source coverage and investigate what changed; do not infer control effectiveness.",
        requiresFreshAssessment: false, canTreatAsReviewed: true };
  }
}
export function caseActionCatalog(): CaseReviewAction[] {
  return CASE_STATES.map(explainCaseState);
}
