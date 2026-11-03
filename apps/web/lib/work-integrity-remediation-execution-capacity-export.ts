import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityExecutionCapacityPlan,
} from "./work-integrity-remediation-execution-capacity";
import type {
  IntegrityExecutionCapacityForecast,
} from "./work-integrity-remediation-execution-capacity-forecast";
export type IntegrityExecutionCapacityExportFormat = "CSV" | "JSON" | "JSONL";
export type IntegrityExecutionCapacityExportSection =
  | "ASSIGNMENTS" | "UNASSIGNED" | "MEMBERS" | "FORECAST_TASKS"
  | "FORECAST_DAYS" | "FORECAST_ACTORS";
export type IntegrityExecutionCapacityExportOptions = {
  format: IntegrityExecutionCapacityExportFormat;
  sections: IntegrityExecutionCapacityExportSection[];
  includeMetadata: boolean;
  includeEmptySections: boolean;
  maximumRows: number;
};
export type IntegrityExecutionCapacityExport = {
  schemaVersion: 1;
  captureId: string;
  format: IntegrityExecutionCapacityExportFormat;
  contentType: string;
  fileName: string;
  content: string;
  rows: number;
  truncated: boolean;
  includedSections: IntegrityExecutionCapacityExportSection[];
  limitation: string;
};
const sections: IntegrityExecutionCapacityExportSection[] = [
  "ASSIGNMENTS", "UNASSIGNED", "MEMBERS", "FORECAST_TASKS",
  "FORECAST_DAYS", "FORECAST_ACTORS",
];
const defaults: IntegrityExecutionCapacityExportOptions = {
  format: "CSV", sections: ["ASSIGNMENTS", "UNASSIGNED", "MEMBERS"],
  includeMetadata: true, includeEmptySections: false,
  maximumRows: 100000,
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid capacity export options.");
  return value as Record<string, unknown>;
}
export function parseIntegrityExecutionCapacityExportOptions(
  value: unknown,
): IntegrityExecutionCapacityExportOptions {
  if (value === undefined) return {
    ...defaults, sections: [...defaults.sections],
  };
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "format", "sections", "includeMetadata",
    "includeEmptySections", "maximumRows",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown capacity export option.");
  const format = raw.format ?? defaults.format;
  if (format !== "CSV" && format !== "JSON" && format !== "JSONL")
    throw new WorkInputError("INVALID", "Unknown capacity export format.");
  const selected = raw.sections === undefined ? defaults.sections :
    raw.sections;
  if (!Array.isArray(selected) || selected.length > sections.length ||
      selected.some(x => !sections.includes(
        x as IntegrityExecutionCapacityExportSection)) ||
      new Set(selected).size !== selected.length)
    throw new WorkInputError("INVALID", "Invalid capacity export sections.");
  for (const key of ["includeMetadata", "includeEmptySections"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid capacity export flag.");
  }
  const maximumRows = raw.maximumRows ?? defaults.maximumRows;
  if (typeof maximumRows !== "number" ||
      !Number.isSafeInteger(maximumRows) || maximumRows < 1 ||
      maximumRows > 100000)
    throw new WorkInputError("INVALID", "Invalid export row limit.");
  return {
    format, sections: selected as IntegrityExecutionCapacityExportSection[],
    includeMetadata: raw.includeMetadata !== false,
    includeEmptySections: raw.includeEmptySections === true,
    maximumRows,
  };
}
type ExportRow = Record<string, string | number | boolean | null>;
function stringify(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return JSON.stringify(value);
}
function safeCsv(value: unknown) {
  let text = stringify(value);
  if (/^[\s]*[=+@\-]/.test(text))
    text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
function row(value: object): ExportRow {
  return Object.fromEntries(Object.entries(value).map(([key, entry]) =>
    [key, typeof entry === "string" || typeof entry === "number" ||
      typeof entry === "boolean" || entry === null ?
      entry : JSON.stringify(entry)])) as ExportRow;
}
function sourceRows(
  plan: IntegrityExecutionCapacityPlan,
  forecast: IntegrityExecutionCapacityForecast | null,
): Record<IntegrityExecutionCapacityExportSection, ExportRow[]> {
  return {
    ASSIGNMENTS: plan.assignments.map(x => row(x)),
    UNASSIGNED: plan.unassigned.map(x => row(x)),
    MEMBERS: plan.members.map(x => row(x)),
    FORECAST_TASKS: forecast?.tasks.map(x => row(x)) ?? [],
    FORECAST_DAYS: forecast?.days.map(x => row(x)) ?? [],
    FORECAST_ACTORS: forecast?.actors.map(x => row(x)) ?? [],
  };
}
function csv(rows: Array<{ section: string; data: ExportRow }>) {
  const columns = [...new Set(rows.flatMap(x => Object.keys(x.data)))].sort();
  const lines = [["section", ...columns].map(safeCsv).join(",")];
  for (const item of rows)
    lines.push([item.section, ...columns.map(x => item.data[x] ?? "")]
      .map(safeCsv).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function exportIntegrityExecutionCapacity(
  plan: IntegrityExecutionCapacityPlan,
  forecast: IntegrityExecutionCapacityForecast | null,
  options: IntegrityExecutionCapacityExportOptions = defaults,
): IntegrityExecutionCapacityExport {
  if (forecast && forecast.captureId !== plan.captureId)
    throw new WorkInputError("INVALID", "Capacity export capture mismatch.");
  if (!forecast && options.sections.some(x => x.startsWith("FORECAST_")))
    throw new WorkInputError("INVALID", "Forecast export requires forecast.");
  const sources = sourceRows(plan, forecast);
  const all = options.sections.flatMap(section =>
    sources[section].length || !options.includeEmptySections ? 
      sources[section].map(data => ({ section, data })) :
      [{ section, data: {} as ExportRow }]);
  const truncated = all.length > options.maximumRows;
  const selected = all.slice(0, options.maximumRows);
  const metadata = {
    schemaVersion: 1, captureId: plan.captureId,
    evaluatedAt: plan.evaluatedAt,
    forecastEvaluatedAt: forecast?.evaluatedAt ?? null,
    rows: selected.length, truncated,
    limitation: "Capacity allocations and forecasts are analytical proposals, not executed assignments or verified security evidence.",
  };
  const format = options.format;
  let content: string;
  if (format === "CSV") {
    content = csv(selected);
  } else if (format === "JSONL") {
    content = [
      ...(options.includeMetadata ?
        [JSON.stringify({ type: "metadata", ...metadata })] : []),
      ...selected.map(x => JSON.stringify({
        type: "row", section: x.section, ...x.data,
      })),
    ].join("\n") + "\n";
  } else {
    content = JSON.stringify({
      ...(options.includeMetadata ? { metadata } : {}),
      rows: selected.map(x => ({
        section: x.section, ...x.data,
      })),
    }, null, 2);
  }
  return {
    schemaVersion: 1, captureId: plan.captureId, format,
    contentType: format === "CSV" ? "text/csv; charset=utf-8" :
      format === "JSONL" ? "application/x-ndjson; charset=utf-8" :
      "application/json; charset=utf-8",
    fileName: "integrity-capacity-" +
      plan.captureId.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100) +
      "." + (format === "CSV" ? "csv" : format === "JSONL" ? "jsonl" : "json"),
    content, rows: selected.length, truncated,
    includedSections: options.sections,
    limitation: metadata.limitation,
  };
}
