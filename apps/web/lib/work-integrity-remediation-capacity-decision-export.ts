import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityCapacityDecisionReport,
  IntegrityCapacityDecisionAudit,
} from "./work-integrity-remediation-capacity-decision";
import type {
  IntegrityCapacitySensitivityReport,
} from "./work-integrity-remediation-capacity-sensitivity";
export type IntegrityCapacityDecisionExportFormat = "CSV" | "JSON" | "JSONL";
export type IntegrityCapacityDecisionExportSection =
  | "DECISIONS" | "SENSITIVITY" | "AUDIT";
export type IntegrityCapacityDecisionExportOptions = {
  format: IntegrityCapacityDecisionExportFormat;
  sections: IntegrityCapacityDecisionExportSection[];
  includeExcluded: boolean;
  maximumRows: number;
};
export type IntegrityCapacityDecisionExport = {
  schemaVersion: 1;
  format: IntegrityCapacityDecisionExportFormat;
  captureId: string;
  fileName: string;
  mediaType: string;
  content: string;
  rows: number;
  truncated: boolean;
  limitation: string;
};
type Cell = string | number | boolean | null;
type Row = {
  section: IntegrityCapacityDecisionExportSection;
  id: string;
  category: string;
  status: string;
  metric: string;
  value: Cell;
  details: string;
};
const formats: IntegrityCapacityDecisionExportFormat[] = [
  "CSV", "JSON", "JSONL",
];
const sections: IntegrityCapacityDecisionExportSection[] = [
  "DECISIONS", "SENSITIVITY", "AUDIT",
];
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid decision export options.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, name: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + name);
  return value;
}
export function parseIntegrityCapacityDecisionExportOptions(
  value: unknown,
): IntegrityCapacityDecisionExportOptions {
  if (value === undefined)
    return {
      format: "JSON", sections: ["DECISIONS"],
      includeExcluded: true, maximumRows: 10000,
    };
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "format", "sections", "includeExcluded", "maximumRows",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown decision export field.");
  const format = raw.format ?? "JSON";
  if (!formats.includes(format as IntegrityCapacityDecisionExportFormat))
    throw new WorkInputError("INVALID", "Invalid decision export format.");
  const selected = raw.sections ?? ["DECISIONS"];
  if (!Array.isArray(selected) || !selected.length ||
      selected.length > sections.length ||
      selected.some(x => !sections.includes(
        x as IntegrityCapacityDecisionExportSection)) ||
      new Set(selected).size !== selected.length)
    throw new WorkInputError("INVALID", "Invalid decision export sections.");
  if (raw.includeExcluded !== undefined &&
      typeof raw.includeExcluded !== "boolean")
    throw new WorkInputError("INVALID", "Invalid export inclusion flag.");
  return {
    format: format as IntegrityCapacityDecisionExportFormat,
    sections: selected as IntegrityCapacityDecisionExportSection[],
    includeExcluded: raw.includeExcluded !== false,
    maximumRows: integer(raw.maximumRows ?? 10000,
      "decision export row limit", 1, 100000),
  };
}
function csvCell(value: Cell): string {
  let text = value === null ? "" : String(value);
  // CSV consumers can execute spreadsheet formulas from untrusted identifiers.
  // Quote the cell after neutralizing formula prefixes, including whitespace.
  if (/^[\s\u0000-\u001f]*[=+@-]/.test(text))
    text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
function decisionRows(
  report: IntegrityCapacityDecisionReport,
  includeExcluded: boolean,
): Row[] {
  const rows: Row[] = [];
  for (const candidate of report.candidates) {
    if (!includeExcluded && !candidate.eligible) continue;
    const base = {
      section: "DECISIONS" as const,
      id: candidate.bundleId,
      category: candidate.interventionIds.join("|"),
      status: candidate.eligible ? "ELIGIBLE" : "EXCLUDED",
      details: candidate.exclusionReasons.join("|"),
    };
    rows.push({ ...base, metric: "score", value: candidate.score });
    rows.push({ ...base, metric: "rank", value: candidate.rank });
    rows.push({ ...base, metric: "completedGain",
      value: candidate.completedGain });
    rows.push({ ...base, metric: "assignedGain",
      value: candidate.assignedGain });
    rows.push({ ...base, metric: "effortGain",
      value: candidate.effortGain });
    rows.push({ ...base, metric: "outsideHorizonGain",
      value: candidate.outsideHorizonGain });
    rows.push({ ...base, metric: "unassignedGain",
      value: candidate.unassignedGain });
    rows.push({ ...base, metric: "pareto",
      value: candidate.pareto });
    rows.push({ ...base, metric: "dominatedBy",
      value: candidate.dominatedBy.join("|") });
  }
  return rows;
}
function sensitivityRows(report: IntegrityCapacitySensitivityReport): Row[] {
  const rows: Row[] = [];
  for (const item of report.observations) {
    const base = {
      section: "SENSITIVITY" as const,
      id: item.variationId, category: item.axis,
      status: item.selectionChanged ? "CHANGED" : "UNCHANGED",
      details: item.selectionReason,
    };
    rows.push({ ...base, metric: "parameterValue",
      value: item.value });
    rows.push({ ...base, metric: "selectedBundleId",
      value: item.selectedBundleId });
    rows.push({ ...base, metric: "selectedScore",
      value: item.selectedScore });
    rows.push({ ...base, metric: "scoreDelta",
      value: item.scoreDelta });
    rows.push({ ...base, metric: "eligibleBundles",
      value: item.eligible });
    rows.push({ ...base, metric: "selectedCompletedGain",
      value: item.selectedCompletedGain });
    rows.push({ ...base, metric: "selectedAssignedGain",
      value: item.selectedAssignedGain });
  }
  return rows;
}
function auditRows(report: IntegrityCapacityDecisionAudit): Row[] {
  const rows: Row[] = [];
  const base = {
    section: "AUDIT" as const,
    id: report.selectedBundleId ?? "NO_SELECTION",
    category: "DECISION_TRACE",
    status: report.warnings.length ? "WARNINGS" : "COMPLETE",
    details: report.warnings.join("|"),
  };
  rows.push({ ...base, metric: "selectedBundleId",
    value: report.selectedBundleId });
  rows.push({ ...base, metric: "portfolioTruncated",
    value: report.completeness.portfolioTruncated });
  rows.push({ ...base, metric: "attributionAvailable",
    value: report.completeness.attributionAvailable });
  rows.push({ ...base, metric: "standaloneAvailable",
    value: report.completeness.standaloneResultsAvailable });
  for (const item of report.interventionStandaloneResults) {
    rows.push({ ...base, id: item.interventionId,
      category: "STANDALONE",
      metric: "assignedDelta", value: item.assignedDelta });
    rows.push({ ...base, id: item.interventionId,
      category: "STANDALONE",
      metric: "completedDelta", value: item.completedDelta });
  }
  for (const item of report.marginalAttribution) {
    rows.push({ ...base, id: item.interventionId,
      category: "ATTRIBUTION",
      metric: "marginalCompletionGain",
      value: item.marginalCompletionGain });
    rows.push({ ...base, id: item.interventionId,
      category: "ATTRIBUTION",
      metric: "marginalAssignedGain",
      value: item.marginalAssignedGain });
  }
  return rows;
}
export function exportIntegrityCapacityDecision(
  decision: IntegrityCapacityDecisionReport,
  sensitivity: IntegrityCapacitySensitivityReport | null,
  audit: IntegrityCapacityDecisionAudit | null,
  options: IntegrityCapacityDecisionExportOptions,
): IntegrityCapacityDecisionExport {
  if (sensitivity && sensitivity.captureId !== decision.captureId ||
      audit && audit.captureId !== decision.captureId)
    throw new WorkInputError("INVALID", "Decision export capture mismatch.");
  if (options.sections.includes("SENSITIVITY") && !sensitivity)
    throw new WorkInputError("INVALID", "Sensitivity export requires analysis.");
  if (options.sections.includes("AUDIT") && !audit)
    throw new WorkInputError("INVALID", "Audit export requires decision audit.");
  const rows: Row[] = [];
  for (const section of options.sections) {
    if (section === "DECISIONS")
      rows.push(...decisionRows(decision, options.includeExcluded));
    else if (section === "SENSITIVITY" && sensitivity)
      rows.push(...sensitivityRows(sensitivity));
    else if (section === "AUDIT" && audit)
      rows.push(...auditRows(audit));
  }
  const selected = rows.slice(0, options.maximumRows);
  const truncated = selected.length < rows.length;
  const metadata = {
    schemaVersion: 1, captureId: decision.captureId,
    evaluatedAt: decision.evaluatedAt,
    selectedBundleId: decision.selectedBundleId,
    sections: options.sections,
    rows: selected.length,
    truncated,
    limitation: "Analytical scenario exports do not authorize execution or establish verified security evidence.",
  };
  const columns: (keyof Row)[] = [
    "section", "id", "category", "status",
    "metric", "value", "details",
  ];
  let content: string;
  let mediaType: string;
  if (options.format === "CSV") {
    const lines = [columns.map(csvCell).join(",")];
    for (const row of selected)
      lines.push(columns.map(key => csvCell(row[key])).join(","));
    content = lines.join("\r\n") + "\r\n";
    mediaType = "text/csv; charset=utf-8";
  } else if (options.format === "JSONL") {
    content = [
      JSON.stringify({ type: "metadata", ...metadata }),
      ...selected.map(row => JSON.stringify({ type: "row", ...row })),
    ].join("\n") + "\n";
    mediaType = "application/x-ndjson; charset=utf-8";
  } else {
    content = JSON.stringify({ metadata, rows: selected }, null, 2);
    mediaType = "application/json; charset=utf-8";
  }
  const safeCapture = decision.captureId.replace(
    /[^A-Za-z0-9_-]/g, "_").slice(0, 80);
  const extension = options.format === "JSONL" ? "jsonl" :
    options.format.toLowerCase();
  return {
    schemaVersion: 1, format: options.format,
    captureId: decision.captureId,
    fileName: "integrity-capacity-decision-" + safeCapture +
      "." + extension,
    mediaType, content, rows: selected.length,
    truncated, limitation: metadata.limitation,
  };
}
