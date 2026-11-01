import { db } from "@cyberpilot/database";
import { canReadWork, WorkInputError, type WorkRole } from "./remediation-work-input";
import {
  loadAuditChain, type AuditChainReport,
} from "./work-integrity-audit-chain";

/**
 * A bounded tenant-scoped audit-review portfolio for actual stored work.
 * Each work history is inspected independently; unavailable source coverage
 * is explicit, and totals are scoped to the selected page of work items.
 */
export type AuditPortfolioScope = {
  organizationId: string; userId: string; role: WorkRole;
};
export type AuditPortfolioOptions = {
  limit: number;
  cursor: string | null;
  onlyReviewed: boolean;
  historyLimit: number;
};
export type AuditPortfolioRow = {
  workItemId: string;
  title: string;
  status: string;
  revision: number;
  assigneeUserId: string | null;
  dueAt: string | null;
  auditEventsRead: number;
  cases: number;
  errors: number;
  warnings: number;
  unknowns: number;
  historyComplete: boolean;
  reviewCoverage: "NO_REVIEW" | "COMPLETE" | "PARTIAL" | "INCONSISTENT";
  action: string;
};
export type AuditPortfolioReport = {
  organizationId: string;
  generatedAt: string;
  filters: AuditPortfolioOptions;
  examinedWorkItems: number;
  nextCursor: string | null;
  rows: AuditPortfolioRow[];
  counts: {
    total: number;
    noReview: number;
    complete: number;
    partial: number;
    inconsistent: number;
    errors: number;
    warnings: number;
    unknowns: number;
  };
  limitations: string[];
};
export function parseAuditPortfolioOptions(raw: Record<string, unknown>): AuditPortfolioOptions {
  const allowed = ["limit", "cursor", "onlyReviewed", "historyLimit"];
  for (const key of Object.keys(raw))
    if (!allowed.includes(key))
      throw new WorkInputError("INVALID", "Unsupported audit portfolio filter.");
  const limit = raw.limit === undefined ? 20 : Number(raw.limit);
  if (![10, 20, 50].includes(limit))
    throw new WorkInputError("INVALID", "Portfolio page size must be 10, 20 or 50.");
  const historyLimit = raw.historyLimit === undefined ? 500 : Number(raw.historyLimit);
  if (![100, 500, 1000, 2000].includes(historyLimit))
    throw new WorkInputError("INVALID", "Unsupported audit history limit.");
  const cursor = raw.cursor === undefined || raw.cursor === "" ? null : raw.cursor;
  if (cursor !== null && (typeof cursor !== "string" ||
      !/^[A-Za-z0-9_-]{5,100}$/.test(cursor)))
    throw new WorkInputError("INVALID", "Invalid work cursor.");
  if (raw.onlyReviewed !== undefined &&
      raw.onlyReviewed !== "true" && raw.onlyReviewed !== "false")
    throw new WorkInputError("INVALID", "Invalid review filter.");
  return {
    limit, historyLimit, cursor: cursor as string | null,
    onlyReviewed: raw.onlyReviewed === "true",
  };
}
export function portfolioCoverage(report: AuditChainReport): AuditPortfolioRow["reviewCoverage"] {
  if (report.totals.errors > 0 || report.malformedRecords > 0) return "INCONSISTENT";
  if (report.recordsRead === 0) return "NO_REVIEW";
  if (!report.historyComplete || report.totals.unknowns > 0) return "PARTIAL";
  return "COMPLETE";
}
export function portfolioNextAction(row: Pick<AuditPortfolioRow,
  "reviewCoverage" | "errors" | "warnings">): string {
  if (row.reviewCoverage === "INCONSISTENT")
    return "Investigate audit source integrity and reconcile broken review links.";
  if (row.reviewCoverage === "PARTIAL")
    return "Read additional authorized audit history before concluding continuity.";
  if (row.reviewCoverage === "NO_REVIEW")
    return "Open the work item and determine whether a human integrity review is required.";
  if (row.warnings > 0)
    return "Review missing actor attribution and revision chronology.";
  return "No audit-chain issue detected in the available source; verify the underlying control separately.";
}
export function buildAuditPortfolio(
  organizationId: string,
  generatedAt: string,
  filters: AuditPortfolioOptions,
  items: readonly {
    id: string;
    title: string;
    status: string;
    revision: number;
    assigneeUserId: string | null;
    dueAt: Date | null;
  }[],
  audits: ReadonlyMap<string, AuditChainReport>,
  nextCursor: string | null,
): AuditPortfolioReport {
  const rows: AuditPortfolioRow[] = [];
  for (const item of items) {
    const audit = audits.get(item.id);
    if (!audit || audit.organizationId !== organizationId || audit.workItemId !== item.id)
      throw new Error("Missing or cross-tenant work audit result.");
    const coverage = portfolioCoverage(audit);
    if (filters.onlyReviewed && coverage === "NO_REVIEW") continue;
    const base = {
      workItemId: item.id, title: item.title, status: item.status,
      revision: item.revision, assigneeUserId: item.assigneeUserId,
      dueAt: item.dueAt?.toISOString() ?? null,
      auditEventsRead: audit.recordsRead,
      cases: audit.totals.cases,
      errors: audit.totals.errors,
      warnings: audit.totals.warnings,
      unknowns: audit.totals.unknowns,
      historyComplete: audit.historyComplete,
      reviewCoverage: coverage,
    };
    rows.push({ ...base, action: portfolioNextAction(base) });
  }
  rows.sort((a, b) => {
    const rank = { INCONSISTENT: 0, PARTIAL: 1, NO_REVIEW: 2, COMPLETE: 3 };
    return rank[a.reviewCoverage] - rank[b.reviewCoverage] ||
      b.errors - a.errors || a.workItemId.localeCompare(b.workItemId);
  });
  const counts = {
    total: rows.length, noReview: 0, complete: 0, partial: 0,
    inconsistent: 0, errors: 0, warnings: 0, unknowns: 0,
  };
  for (const row of rows) {
    if (row.reviewCoverage === "NO_REVIEW") counts.noReview++;
    if (row.reviewCoverage === "COMPLETE") counts.complete++;
    if (row.reviewCoverage === "PARTIAL") counts.partial++;
    if (row.reviewCoverage === "INCONSISTENT") counts.inconsistent++;
    counts.errors += row.errors;
    counts.warnings += row.warnings;
    counts.unknowns += row.unknowns;
  }
  return {
    organizationId, generatedAt, filters,
    examinedWorkItems: items.length, nextCursor, rows, counts,
    limitations: [
      "Only work items from the selected tenant-scoped cursor page are counted.",
      "Filtering for reviewed work is applied after the bounded source page is inspected.",
      "Each work item has an independent bounded audit history limit.",
      "An internally complete decision chain does not verify a remediation or security control.",
      ...(nextCursor ? ["Additional work-item pages exist beyond this result."] : []),
    ],
  };
}
export async function loadAuditPortfolio(
  scope: AuditPortfolioScope,
  raw: Record<string, unknown>,
  now = new Date(),
): Promise<AuditPortfolioReport> {
  if (!scope.organizationId || !scope.userId || !canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Organization membership required.");
  const filters = parseAuditPortfolioOptions(raw);
  const items = await db.remediationWorkItem.findMany({
    where: { organizationId: scope.organizationId },
    orderBy: [{ id: "asc" }],
    ...(filters.cursor ? { cursor: { id: filters.cursor }, skip: 1 } : {}),
    take: filters.limit + 1,
    select: {
      id: true, title: true, status: true, revision: true,
      assigneeUserId: true, dueAt: true,
    },
  });
  const more = items.length > filters.limit;
  const selected = items.slice(0, filters.limit);
  const audits = new Map<string, AuditChainReport>();
  // The bounded page caps query fanout; each call retains explicit tenant scope.
  // Work-item revisions are checked against the values returned by each audit.
  for (const item of selected) {
    const audit = await loadAuditChain(scope, {
      workItemId: item.id, limit: String(filters.historyLimit),
    }, now);
    audits.set(item.id, audit);
  }
  return buildAuditPortfolio(
    scope.organizationId, now.toISOString(), filters, selected, audits,
    more ? selected[selected.length - 1]?.id ?? null : null,
  );
}
export function auditPortfolioCsv(report: AuditPortfolioReport): string {
  const quote = (value: unknown) => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const columns = [
    "workItemId", "title", "status", "revision", "assigneeUserId", "dueAt",
    "reviewCoverage", "auditEventsRead", "cases", "errors",
    "warnings", "unknowns", "historyComplete", "recommendedAction",
  ];
  const lines = [columns.map(quote).join(",")];
  for (const row of report.rows) {
    lines.push([
      row.workItemId, row.title, row.status, row.revision,
      row.assigneeUserId, row.dueAt, row.reviewCoverage, row.auditEventsRead,
      row.cases, row.errors, row.warnings, row.unknowns,
      row.historyComplete, row.action,
    ].map(quote).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
