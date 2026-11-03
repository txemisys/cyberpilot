import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  analyzeIntegrityLinkEvents, filterLinkAnalyticsEvents, parseLinkAnalyticsQuery,
  sortLinkAnalyticsEvents, type LinkAnalyticsQuery, type LinkAnalyticsReport,
} from "./work-integrity-link-analytics";
import { WorkInputError } from "./remediation-work-input";

export type IntegrityLinkExportFormat = "csv" | "jsonl" | "json";
export type IntegrityLinkExportKind = "events" | "cases" | "work" | "actors" | "days";
export type IntegrityLinkExportOptions = {
  format: IntegrityLinkExportFormat;
  kind: IntegrityLinkExportKind;
  query: LinkAnalyticsQuery;
  maxRows: number;
};
export type IntegrityLinkExportResult = {
  content: string;
  contentType: string;
  filename: string;
  rows: number;
  truncated: boolean;
};
type ExportRow = Record<string, string | number | boolean | null>;
const EVENT_COLUMNS = [
  "auditId", "originalAuditId", "action", "captureId", "caseKey",
  "workItemId", "actorUserId", "occurredAt",
] as const;
const CASE_COLUMNS = [
  "caseKey", "totalLinks", "activeLinks", "withdrawnLinks",
  "workItemIds", "lastActivityAt",
] as const;
const WORK_COLUMNS = [
  "workItemId", "totalLinks", "activeLinks", "withdrawnLinks",
  "caseKeys", "lastActivityAt",
] as const;
const ACTOR_COLUMNS = [
  "actorUserId", "linksCreated", "withdrawals", "lastActivityAt",
] as const;
const DAY_COLUMNS = ["day", "linksCreated", "withdrawals"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
export function parseIntegrityLinkExportOptions(value: unknown): IntegrityLinkExportOptions {
  if (!isRecord(value)) throw new WorkInputError("INVALID", "Invalid export options.");
  const allowed = new Set(["format", "kind", "maxRows", "caseKey",
    "workItemId", "actorUserId", "action", "since", "until", "sort"]);
  if (Object.keys(value).some(key => !allowed.has(key)))
    throw new WorkInputError("INVALID", "Unknown export option.");
  const format = value.format ?? "csv";
  if (format !== "csv" && format !== "jsonl" && format !== "json")
    throw new WorkInputError("INVALID", "Invalid export format.");
  const kind = value.kind ?? "events";
  if (kind !== "events" && kind !== "cases" && kind !== "work" &&
      kind !== "actors" && kind !== "days")
    throw new WorkInputError("INVALID", "Invalid export kind.");
  const maxRows = value.maxRows ?? 10000;
  if (!Number.isSafeInteger(maxRows) || (maxRows as number) < 1 ||
      (maxRows as number) > 100000)
    throw new WorkInputError("INVALID", "Invalid export row limit.");
  const query = parseLinkAnalyticsQuery({
    ...Object.fromEntries(Object.entries(value).filter(([key]) =>
      ["caseKey", "workItemId", "actorUserId", "action", "since", "until", "sort"].includes(key))),
    offset: 0, limit: 1000,
  });
  return {
    format, kind, maxRows: maxRows as number, query,
  };
}
function neutralizeSpreadsheetFormula(value: string): string {
  const trimmed = value.trimStart();
  if (/^[=+@-]/.test(trimmed)) return "'" + value;
  return value;
}
export function escapeIntegrityCsvCell(value: string | number | boolean | null): string {
  if (value === null) return "";
  const text = neutralizeSpreadsheetFormula(String(value));
  if (/[",\r\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
  return text;
}
function toCsv(rows: readonly ExportRow[], columns: readonly string[]): string {
  const lines = [columns.map(escapeIntegrityCsvCell).join(",")];
  for (const row of rows) {
    lines.push(columns.map(column => escapeIntegrityCsvCell(row[column] ?? null)).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
function toJsonLines(rows: readonly ExportRow[]): string {
  return rows.map(row => JSON.stringify(row)).join("\n") + (rows.length ? "\n" : "");
}
function eventRows(events: readonly IntegrityLinkHistoryEvent[]): ExportRow[] {
  return events.map(event => ({
    auditId: event.auditId,
    originalAuditId: event.originalAuditId,
    action: event.action,
    captureId: event.captureId,
    caseKey: event.caseKey,
    workItemId: event.workItemId,
    actorUserId: event.actorUserId,
    occurredAt: event.occurredAt,
  }));
}
function caseRows(report: LinkAnalyticsReport): ExportRow[] {
  return report.cases.map(item => ({
    caseKey: item.caseKey, totalLinks: item.totalLinks,
    activeLinks: item.activeLinks, withdrawnLinks: item.withdrawnLinks,
    workItemIds: item.workItemIds.join(";"),
    lastActivityAt: item.lastActivityAt,
  }));
}
function workRows(report: LinkAnalyticsReport): ExportRow[] {
  return report.workItems.map(item => ({
    workItemId: item.workItemId, totalLinks: item.totalLinks,
    activeLinks: item.activeLinks, withdrawnLinks: item.withdrawnLinks,
    caseKeys: item.caseKeys.join(";"),
    lastActivityAt: item.lastActivityAt,
  }));
}
function actorRows(report: LinkAnalyticsReport): ExportRow[] {
  return report.actors.map(item => ({
    actorUserId: item.actorUserId, linksCreated: item.linksCreated,
    withdrawals: item.withdrawals, lastActivityAt: item.lastActivityAt,
  }));
}
function dayRows(report: LinkAnalyticsReport): ExportRow[] {
  return report.days.map(item => ({
    day: item.day, linksCreated: item.linksCreated,
    withdrawals: item.withdrawals,
  }));
}
export function buildIntegrityLinkExport(
  events: readonly IntegrityLinkHistoryEvent[],
  options: IntegrityLinkExportOptions,
  captureId: string,
): IntegrityLinkExportResult {
  if (!/^[a-zA-Z0-9_-]{5,100}$/.test(captureId))
    throw new WorkInputError("INVALID", "Invalid export capture ID.");
  const filteredEvents = filterLinkAnalyticsEvents(events, options.query.filter);
  const report = analyzeIntegrityLinkEvents(filteredEvents);
  const selected = options.kind === "events" ?
    eventRows(sortLinkAnalyticsEvents(
      filteredEvents, options.query.sort,
    )) :
    options.kind === "cases" ? caseRows(report) :
    options.kind === "work" ? workRows(report) :
    options.kind === "actors" ? actorRows(report) : dayRows(report);
  const columns = options.kind === "events" ? EVENT_COLUMNS :
    options.kind === "cases" ? CASE_COLUMNS :
    options.kind === "work" ? WORK_COLUMNS :
    options.kind === "actors" ? ACTOR_COLUMNS : DAY_COLUMNS;
  const truncated = selected.length > options.maxRows;
  const rows = selected.slice(0, options.maxRows);
  const content = options.format === "csv" ? toCsv(rows, columns) :
    options.format === "jsonl" ? toJsonLines(rows) :
    JSON.stringify({
      schemaVersion: 1, captureId, kind: options.kind,
      exportedRows: rows.length, totalRows: selected.length, truncated,
      rows,
    }, null, 2);
  const contentType = options.format === "csv" ? "text/csv; charset=utf-8" :
    options.format === "jsonl" ? "application/x-ndjson; charset=utf-8" :
    "application/json; charset=utf-8";
  const extension = options.format === "csv" ? "csv" :
    options.format === "jsonl" ? "jsonl" : "json";
  return {
    content, contentType, filename: `integrity-links-${captureId}-${options.kind}.${extension}`,
    rows: rows.length, truncated,
  };
}
