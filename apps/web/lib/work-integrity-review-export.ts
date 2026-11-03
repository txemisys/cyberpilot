import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  reviewIntegrityLinks, buildIntegrityReviewMatrix,
  type LinkReviewReport, type LinkReviewFinding,
  type LinkReviewAssociation,
} from "./work-integrity-link-review";
import {
  buildIntegrityReviewTimeline, type IntegrityReviewTimeline,
} from "./work-integrity-link-timeline";

export type IntegrityReviewExportFormat = "csv" | "json" | "jsonl";
export type IntegrityReviewExportKind =
  | "associations" | "findings" | "cases" | "work" | "actors" | "trends" | "timeline";
export type IntegrityReviewExportOptions = {
  format: IntegrityReviewExportFormat;
  kind: IntegrityReviewExportKind;
  maxRows: number;
  checkpoints?: string[];
};
export type IntegrityReviewExport = {
  content: string;
  contentType: string;
  filename: string;
  rows: number;
  totalRows: number;
  truncated: boolean;
};
type ExportRow = Record<string, string | number | boolean | null>;
const formats = ["csv", "json", "jsonl"] as const;
const kinds = ["associations", "findings", "cases", "work", "actors", "trends", "timeline"] as const;
function validCheckpoint(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
export function parseIntegrityReviewExportOptions(value: unknown): IntegrityReviewExportOptions {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Export options must be an object.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key =>
    !["format", "kind", "maxRows", "checkpoints"].includes(key)))
    throw new WorkInputError("INVALID", "Unknown review export option.");
  const format = raw.format ?? "csv";
  const kind = raw.kind ?? "associations";
  const maxRows = raw.maxRows ?? 10000;
  if (!formats.some(x => x === format))
    throw new WorkInputError("INVALID", "Unsupported review export format.");
  if (!kinds.some(x => x === kind))
    throw new WorkInputError("INVALID", "Unsupported review export kind.");
  if (!Number.isSafeInteger(maxRows) || (maxRows as number) < 1 ||
      (maxRows as number) > 100000)
    throw new WorkInputError("INVALID", "Invalid review export row limit.");
  let checkpoints: string[] | undefined;
  if (raw.checkpoints !== undefined) {
    if (!Array.isArray(raw.checkpoints) || raw.checkpoints.length < 1 ||
        raw.checkpoints.length > 366 || !raw.checkpoints.every(validCheckpoint))
      throw new WorkInputError("INVALID", "Invalid timeline checkpoints.");
    checkpoints = [...raw.checkpoints];
  }
  if (kind === "timeline" && !checkpoints)
    throw new WorkInputError("INVALID", "Timeline export requires checkpoints.");
  if (kind !== "timeline" && checkpoints)
    throw new WorkInputError("INVALID", "Checkpoints only apply to timeline exports.");
  return {
    format: format as IntegrityReviewExportFormat,
    kind: kind as IntegrityReviewExportKind,
    maxRows: maxRows as number,
    ...(checkpoints ? { checkpoints } : {}),
  };
}
function safeCell(value: string | number | boolean | null): string {
  if (value === null) return "";
  const raw = String(value);
  // Prevent spreadsheet formula evaluation even after leading whitespace.
  const escaped = /^[\s]*[=+@\-]/.test(raw) ? "'" + raw : raw;
  return '"' + escaped.replace(/"/g, '""') + '"';
}
function serializeRows(
  rows: readonly ExportRow[], columns: readonly string[],
  format: IntegrityReviewExportFormat,
): string {
  if (format === "json") return JSON.stringify(rows, null, 2) + "\n";
  if (format === "jsonl") return rows.map(row => JSON.stringify(row)).join("\n") +
    (rows.length ? "\n" : "");
  return [
    columns.map(safeCell).join(","),
    ...rows.map(row => columns.map(column => safeCell(row[column] ?? null)).join(",")),
  ].join("\r\n") + "\r\n";
}
function associationRow(x: LinkReviewAssociation): ExportRow {
  return {
    auditId: x.auditId, captureId: x.captureId, caseKey: x.caseKey,
    workItemId: x.workItemId, state: x.state,
    createdAt: x.createdAt, createdBy: x.createdBy,
    withdrawnAt: x.withdrawnAt, withdrawnBy: x.withdrawnBy,
    withdrawalAuditId: x.withdrawalAuditId,
  };
}
function findingRow(x: LinkReviewFinding): ExportRow {
  return {
    auditId: x.auditId, code: x.code, severity: x.severity,
    captureId: x.captureId, caseKey: x.caseKey, workItemId: x.workItemId,
    relatedAuditId: x.relatedAuditId, explanation: x.explanation,
  };
}
function rowsForReport(
  report: LinkReviewReport, kind: IntegrityReviewExportKind,
  timeline?: IntegrityReviewTimeline,
): ExportRow[] {
  if (kind === "associations") return report.associations.map(associationRow);
  if (kind === "findings") return report.findings.map(findingRow);
  const matrix = buildIntegrityReviewMatrix(report);
  if (kind === "cases")
    return matrix.cases.map(x => ({
      caseKey: x.caseKey, active: x.active, withdrawn: x.withdrawn,
      workItemIds: x.workItemIds.join(";"), findings: x.findings,
      lastActivityAt: x.lastActivityAt,
    }));
  if (kind === "work")
    return matrix.workItems.map(x => ({
      workItemId: x.workItemId, active: x.active, withdrawn: x.withdrawn,
      caseKeys: x.caseKeys.join(";"), findings: x.findings,
      lastActivityAt: x.lastActivityAt,
    }));
  if (kind === "actors")
    return matrix.actors.map(x => ({
      actorUserId: x.actorUserId, created: x.created,
      withdrawn: x.withdrawn, firstActivityAt: x.firstActivityAt,
      lastActivityAt: x.lastActivityAt,
    }));
  if (kind === "trends")
    return matrix.trends.map(x => ({
      day: x.day, created: x.created, withdrawn: x.withdrawn,
      activeAtEnd: x.activeAtEnd,
    }));
  return (timeline?.intervals ?? []).map(x => ({
    from: x.from, to: x.to, openingActive: x.openingActive,
    closingActive: x.closingActive, linksCreated: x.linksCreated,
    linksWithdrawn: x.linksWithdrawn, netChange: x.netChange,
    casesChanged: x.casesChanged.join(";"),
    workItemsChanged: x.workItemsChanged.join(";"),
  }));
}
const columns: Record<IntegrityReviewExportKind, string[]> = {
  associations: [
    "auditId", "captureId", "caseKey", "workItemId", "state", "createdAt",
    "createdBy", "withdrawnAt", "withdrawnBy", "withdrawalAuditId",
  ],
  findings: [
    "auditId", "code", "severity", "captureId", "caseKey",
    "workItemId", "relatedAuditId", "explanation",
  ],
  cases: ["caseKey", "active", "withdrawn", "workItemIds", "findings", "lastActivityAt"],
  work: ["workItemId", "active", "withdrawn", "caseKeys", "findings", "lastActivityAt"],
  actors: ["actorUserId", "created", "withdrawn", "firstActivityAt", "lastActivityAt"],
  trends: ["day", "created", "withdrawn", "activeAtEnd"],
  timeline: [
    "from", "to", "openingActive", "closingActive", "linksCreated",
    "linksWithdrawn", "netChange", "casesChanged", "workItemsChanged",
  ],
};
export function buildIntegrityReviewExport(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
  options: IntegrityReviewExportOptions,
): IntegrityReviewExport {
  const report = reviewIntegrityLinks(captureId, events);
  const timeline = options.kind === "timeline"
    ? buildIntegrityReviewTimeline(captureId, events, options.checkpoints ?? [])
    : undefined;
  const rows = rowsForReport(report, options.kind, timeline);
  const visible = rows.slice(0, options.maxRows);
  const extension = options.format === "jsonl" ? "jsonl" : options.format;
  const contentType = options.format === "csv"
    ? "text/csv; charset=utf-8"
    : options.format === "jsonl"
      ? "application/x-ndjson; charset=utf-8"
      : "application/json; charset=utf-8";
  return {
    content: serializeRows(visible, columns[options.kind], options.format),
    contentType,
    filename: "integrity-review-" + options.kind + "-" + captureId + "." + extension,
    rows: visible.length, totalRows: rows.length,
    truncated: visible.length < rows.length,
  };
}
export function reviewExportManifest(
  captureId: string,
  events: readonly IntegrityLinkHistoryEvent[],
) {
  const report = reviewIntegrityLinks(captureId, events);
  const matrix = buildIntegrityReviewMatrix(report);
  return {
    schemaVersion: 1, captureId,
    availableKinds: [...kinds],
    availableFormats: [...formats],
    totals: {
      associations: report.associations.length,
      findings: report.findings.length,
      cases: matrix.cases.length,
      work: matrix.workItems.length,
      actors: matrix.actors.length,
      trends: matrix.trends.length,
    },
    integrity: report.counts,
  };
}
