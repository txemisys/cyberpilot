import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationPlan, IntegrityRemediationCandidate,
} from "./work-integrity-remediation-plan";
import type {
  IntegrityRemediationHistory,
} from "./work-integrity-remediation-history";
import type {
  IntegrityRemediationWorkloadReport,
} from "./work-integrity-remediation-capacity";

export type IntegrityRemediationExportFormat = "csv" | "json" | "jsonl";
export type IntegrityRemediationExportDataset =
  | "candidates" | "trends" | "transitions" | "workload"
  | "priority-summary" | "case-summary" | "action-summary";
export type IntegrityRemediationExportRequest = {
  format: IntegrityRemediationExportFormat;
  datasets: IntegrityRemediationExportDataset[];
  includeAdvisory: boolean;
  includeBlocked: boolean;
  maximumRows: number;
};
export type IntegrityRemediationExportFile = {
  name: string;
  contentType: string;
  body: string;
  rows: number;
  truncated: boolean;
};
export type IntegrityRemediationExportBundle = {
  captureId: string;
  format: IntegrityRemediationExportFormat;
  files: IntegrityRemediationExportFile[];
  totalRows: number;
  truncatedDatasets: string[];
};
const datasets: IntegrityRemediationExportDataset[] = [
  "candidates", "trends", "transitions", "workload",
  "priority-summary", "case-summary", "action-summary",
];
const formats: IntegrityRemediationExportFormat[] = ["csv", "json", "jsonl"];
const fieldOrder: Record<IntegrityRemediationExportDataset, string[]> = {
  candidates: [
    "captureId", "id", "action", "priority", "caseKey", "workItemId",
    "auditId", "policyIndex", "executable", "blocked", "blockedBy",
    "dependencies", "reasonCodes", "estimatedRiskReduction", "explanation",
  ],
  trends: [
    "captureId", "id", "action", "caseKey", "workItemId", "firstSeenAt",
    "lastSeenAt", "observedCheckpoints", "missingCheckpoints", "current",
    "everUrgent", "currentPriority", "longestOpenStreak",
    "longestResolvedStreak", "priorityHistory",
  ],
  transitions: [
    "captureId", "from", "to", "riskCaseDelta", "riskWorkDelta",
    "policyFailureDelta", "activeAssociationDelta",
    "withdrawnAssociationDelta", "candidateDelta",
    "introduced", "resolved", "reprioritized",
    "newlyBlocked", "newlyExecutable",
    "newUrgentCandidates", "resolvedUrgentCandidates",
  ],
  workload: [
    "captureId", "kind", "group", "candidates", "urgent", "blocked",
    "advisory", "riskPoints", "cases", "workItems", "actions",
  ],
  "priority-summary": [
    "captureId", "priority", "candidates", "advisory",
    "blocked", "riskPoints", "cases", "workItems",
  ],
  "case-summary": [
    "captureId", "caseKey", "candidates", "urgent",
    "blocked", "advisory", "riskPoints", "actions",
  ],
  "action-summary": [
    "captureId", "action", "candidates", "urgent",
    "blocked", "advisory", "riskPoints", "cases", "workItems",
  ],
};
type ExportRow = Record<string, string | number | boolean | null>;
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected remediation export request.");
  return value as Record<string, unknown>;
}
export function parseIntegrityRemediationExportRequest(
  value: unknown,
): IntegrityRemediationExportRequest {
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "format", "datasets", "includeAdvisory", "includeBlocked", "maximumRows",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown export request field.");
  const format = raw.format ?? "csv";
  if (!formats.includes(format as IntegrityRemediationExportFormat))
    throw new WorkInputError("INVALID", "Unsupported export format.");
  const selected = raw.datasets ?? ["candidates"];
  if (!Array.isArray(selected) || selected.length === 0 ||
      selected.length > datasets.length ||
      selected.some(x => !datasets.includes(x)))
    throw new WorkInputError("INVALID", "Invalid export datasets.");
  if (raw.includeAdvisory !== undefined && typeof raw.includeAdvisory !== "boolean")
    throw new WorkInputError("INVALID", "Invalid advisory filter.");
  if (raw.includeBlocked !== undefined && typeof raw.includeBlocked !== "boolean")
    throw new WorkInputError("INVALID", "Invalid blocked filter.");
  const maximumRows = raw.maximumRows ?? 10000;
  if (!Number.isSafeInteger(maximumRows) || (maximumRows as number) < 1 ||
      (maximumRows as number) > 100000)
    throw new WorkInputError("INVALID", "Invalid export row limit.");
  return {
    format: format as IntegrityRemediationExportFormat,
    datasets: [...new Set(selected)] as IntegrityRemediationExportDataset[],
    includeAdvisory: raw.includeAdvisory !== false,
    includeBlocked: raw.includeBlocked !== false,
    maximumRows: maximumRows as number,
  };
}
function csvCell(value: ExportRow[string]) {
  let raw = value === null ? "" : String(value);
  if (/^[\s]*[=+@\-]/.test(raw)) raw = "'" + raw;
  return '"' + raw.replace(/"/g, '""') + '"';
}
function encodeCsv(rows: readonly ExportRow[], columns: readonly string[]) {
  return [
    columns.map(csvCell).join(","),
    ...rows.map(row => columns.map(key => csvCell(row[key] ?? null)).join(",")),
  ].join("\r\n") + "\r\n";
}
function encodeJson(rows: readonly ExportRow[]) {
  return JSON.stringify(rows);
}
function encodeJsonl(rows: readonly ExportRow[]) {
  return rows.map(x => JSON.stringify(x)).join("\n") +
    (rows.length ? "\n" : "");
}
function serialize(
  rows: readonly ExportRow[],
  columns: readonly string[],
  format: IntegrityRemediationExportFormat,
) {
  if (format === "csv") return encodeCsv(rows, columns);
  if (format === "json") return encodeJson(rows);
  return encodeJsonl(rows);
}
function candidateRow(
  captureId: string,
  item: IntegrityRemediationCandidate,
): ExportRow {
  return {
    captureId, id: item.id, action: item.action,
    priority: item.priority, caseKey: item.caseKey,
    workItemId: item.workItemId, auditId: item.auditId,
    policyIndex: item.policyIndex, executable: item.executable,
    blocked: item.blockedBy.length > 0,
    blockedBy: JSON.stringify(item.blockedBy),
    dependencies: JSON.stringify(item.dependencies),
    reasonCodes: JSON.stringify(item.reasonCodes),
    estimatedRiskReduction: item.estimatedRiskReduction,
    explanation: item.explanation,
  };
}
function candidateRows(
  plan: IntegrityRemediationPlan,
  request: IntegrityRemediationExportRequest,
): ExportRow[] {
  return plan.candidates.filter(x =>
    (request.includeAdvisory || x.executable) &&
    (request.includeBlocked || x.blockedBy.length === 0))
    .map(x => candidateRow(plan.captureId, x));
}
function trendRows(history: IntegrityRemediationHistory): ExportRow[] {
  return history.trends.map(x => ({
    captureId: history.captureId, id: x.id,
    action: x.action, caseKey: x.caseKey,
    workItemId: x.workItemId,
    firstSeenAt: x.firstSeenAt, lastSeenAt: x.lastSeenAt,
    observedCheckpoints: x.observedCheckpoints,
    missingCheckpoints: x.missingCheckpoints,
    current: x.current, everUrgent: x.everUrgent,
    currentPriority: x.currentPriority,
    longestOpenStreak: x.longestOpenStreak,
    longestResolvedStreak: x.longestResolvedStreak,
    priorityHistory: JSON.stringify(x.priorityHistory),
  }));
}
function transitionRows(history: IntegrityRemediationHistory): ExportRow[] {
  return history.transitions.map(x => ({
    captureId: history.captureId, from: x.from, to: x.to,
    riskCaseDelta: x.riskCaseDelta,
    riskWorkDelta: x.riskWorkDelta,
    policyFailureDelta: x.policyFailureDelta,
    activeAssociationDelta: x.activeAssociationDelta,
    withdrawnAssociationDelta: x.withdrawnAssociationDelta,
    candidateDelta: x.candidateDelta,
    introduced: JSON.stringify(x.delta.added.map(y => y.id)),
    resolved: JSON.stringify(x.delta.removed.map(y => y.id)),
    reprioritized: JSON.stringify(x.delta.reprioritized),
    newlyBlocked: JSON.stringify(x.delta.newlyBlocked),
    newlyExecutable: JSON.stringify(x.delta.newlyExecutable),
    newUrgentCandidates: JSON.stringify(x.newUrgentCandidates),
    resolvedUrgentCandidates: JSON.stringify(x.resolvedUrgentCandidates),
  }));
}
function workloadRows(
  report: IntegrityRemediationWorkloadReport,
): ExportRow[] {
  return [
    ...report.byCase.map(x => ({ kind: "CASE", ...x })),
    ...report.byWorkItem.map(x => ({ kind: "WORK", ...x })),
    ...report.byAction.map(x => ({ kind: "ACTION", ...x })),
    { kind: "UNASSIGNED", ...report.unassigned },
  ].map(x => ({
    captureId: report.captureId, kind: x.kind,
    group: x.group, candidates: x.candidates,
    urgent: x.urgent, blocked: x.blocked,
    advisory: x.advisory, riskPoints: x.riskPoints,
    cases: JSON.stringify(x.cases),
    workItems: JSON.stringify(x.workItems),
    actions: JSON.stringify(x.actions),
  }));
}
function priorityRows(plan: IntegrityRemediationPlan): ExportRow[] {
  return (["P0", "P1", "P2", "P3"] as const).map(priority => {
    const rows = plan.candidates.filter(x => x.priority === priority);
    return {
      captureId: plan.captureId, priority, candidates: rows.length,
      advisory: rows.filter(x => !x.executable).length,
      blocked: rows.filter(x => x.blockedBy.length > 0).length,
      riskPoints: rows.reduce((sum, x) => sum + x.estimatedRiskReduction, 0),
      cases: new Set(rows.flatMap(x => x.caseKey ? [x.caseKey] : [])).size,
      workItems: new Set(rows.flatMap(x => x.workItemId ? [x.workItemId] : [])).size,
    };
  });
}
function caseRows(report: IntegrityRemediationWorkloadReport): ExportRow[] {
  return report.byCase.map(x => ({
    captureId: report.captureId, caseKey: x.group,
    candidates: x.candidates, urgent: x.urgent,
    blocked: x.blocked, advisory: x.advisory,
    riskPoints: x.riskPoints, actions: JSON.stringify(x.actions),
  }));
}
function actionRows(report: IntegrityRemediationWorkloadReport): ExportRow[] {
  return report.byAction.map(x => ({
    captureId: report.captureId, action: x.group,
    candidates: x.candidates, urgent: x.urgent,
    blocked: x.blocked, advisory: x.advisory,
    riskPoints: x.riskPoints,
    cases: JSON.stringify(x.cases),
    workItems: JSON.stringify(x.workItems),
  }));
}
function rowsFor(
  dataset: IntegrityRemediationExportDataset,
  plan: IntegrityRemediationPlan,
  request: IntegrityRemediationExportRequest,
  history: IntegrityRemediationHistory | undefined,
  workload: IntegrityRemediationWorkloadReport | undefined,
): ExportRow[] {
  if (dataset === "candidates") return candidateRows(plan, request);
  if (dataset === "priority-summary") return priorityRows(plan);
  if (dataset === "trends" || dataset === "transitions") {
    if (!history)
      throw new WorkInputError("INVALID", "History required for trend exports.");
    if (history.captureId !== plan.captureId)
      throw new WorkInputError("INVALID", "History capture mismatch.");
    return dataset === "trends" ? trendRows(history) : transitionRows(history);
  }
  if (!workload)
    throw new WorkInputError("INVALID", "Workload required for summary exports.");
  if (workload.captureId !== plan.captureId)
    throw new WorkInputError("INVALID", "Workload capture mismatch.");
  if (dataset === "workload") return workloadRows(workload);
  if (dataset === "case-summary") return caseRows(workload);
  return actionRows(workload);
}
export function exportIntegrityRemediation(
  plan: IntegrityRemediationPlan,
  request: IntegrityRemediationExportRequest,
  history?: IntegrityRemediationHistory,
  workload?: IntegrityRemediationWorkloadReport,
): IntegrityRemediationExportBundle {
  const files: IntegrityRemediationExportFile[] = [];
  const truncatedDatasets: string[] = [];
  for (const dataset of request.datasets) {
    const all = rowsFor(dataset, plan, request, history, workload);
    const rows = all.slice(0, request.maximumRows);
    const truncated = rows.length !== all.length;
    if (truncated) truncatedDatasets.push(dataset);
    const extension = request.format;
    files.push({
      name: "integrity-remediation-" + dataset + "." + extension,
      contentType: request.format === "csv" ? "text/csv; charset=utf-8" :
        request.format === "json" ? "application/json; charset=utf-8" :
        "application/x-ndjson; charset=utf-8",
      body: serialize(rows, fieldOrder[dataset], request.format),
      rows: rows.length, truncated,
    });
  }
  return {
    captureId: plan.captureId, format: request.format,
    files, totalRows: files.reduce((sum, x) => sum + x.rows, 0),
    truncatedDatasets,
  };
}
