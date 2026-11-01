import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { inspectCaptureQuality } from "./work-integrity-capture-quality";

export type CatalogEntry = {
  source: string;
  capturedAt: string;
  complete: boolean;
  safeToTreatAsComplete: boolean;
  cases: number;
  blockers: number;
  warnings: number;
  activeCases: number;
  reviewedCases: number;
  criticalCases: number;
  distinctWorkItems: number;
};
export type CatalogFilter = {
  source?: string;
  from?: string;
  through?: string;
  completeness?: "all" | "complete" | "incomplete";
  minCases?: number;
  onlyQualityProblems?: boolean;
  sort?: "newest" | "oldest" | "cases-desc" | "problems-desc";
  offset?: number;
  limit?: number;
};
export type SnapshotCatalog = {
  organizationId: string;
  total: number;
  matched: number;
  offset: number;
  limit: number;
  entries: CatalogEntry[];
  sources: Array<{ source: string; captures: number; latest: string; incomplete: number }>;
  warnings: string[];
};
function date(value: string, label: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`Invalid ${label}.`);
  return parsed;
}
function count(value: number | undefined, fallback: number, max: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 0 || result > max)
    throw new Error("Invalid catalog pagination or count.");
  return result;
}
export function buildSnapshotCatalog(
  input: readonly unknown[], organizationId: string, filter: CatalogFilter = {},
): SnapshotCatalog {
  if (!organizationId || organizationId.length > 256)
    throw new Error("Authenticated organization is required.");
  if (input.length > 10000) throw new Error("Snapshot catalog limit exceeded.");
  const offset = count(filter.offset, 0, 10000);
  const limit = count(filter.limit, 100, 1000);
  const minCases = count(filter.minCases, 0, 10000);
  const from = filter.from === undefined ? -Infinity : date(filter.from, "from date");
  const through = filter.through === undefined ? Infinity : date(filter.through, "through date");
  if (from > through) throw new Error("Reversed catalog date range.");
  const captures = input.map(value => parseCaseSnapshot(value));
  const identities = new Set<string>();
  const sources = new Map<string, { source: string; captures: number; latest: string; incomplete: number }>();
  const entries: CatalogEntry[] = [];
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization snapshot catalog is forbidden.");
    const identity = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (identities.has(identity)) throw new Error("Duplicate catalog snapshot identity.");
    identities.add(identity);
    const current = sources.get(capture.source) ?? {
      source: capture.source, captures: 0, latest: capture.capturedAt, incomplete: 0,
    };
    current.captures++;
    if (Date.parse(capture.capturedAt) > Date.parse(current.latest))
      current.latest = capture.capturedAt;
    if (!capture.complete) current.incomplete++;
    sources.set(capture.source, current);
    const quality = inspectCaptureQuality(capture);
    entries.push({
      source: capture.source, capturedAt: capture.capturedAt,
      complete: capture.complete, safeToTreatAsComplete: quality.safeToTreatAsComplete,
      cases: capture.cases.length, blockers: quality.blockers, warnings: quality.warnings,
      activeCases: capture.cases.filter(row => !row.historicalOnly).length,
      reviewedCases: capture.cases.filter(row => row.reviewEventId !== null).length,
      criticalCases: capture.cases.filter(row => row.severity === "critical").length,
      distinctWorkItems: new Set(capture.cases.map(row => row.workItemId)).size,
    });
  }
  const matched = entries.filter(entry =>
    (filter.source === undefined || entry.source === filter.source) &&
    Date.parse(entry.capturedAt) >= from && Date.parse(entry.capturedAt) <= through &&
    (filter.completeness === undefined || filter.completeness === "all" ||
      (filter.completeness === "complete" ? entry.complete : !entry.complete)) &&
    entry.cases >= minCases &&
    (!filter.onlyQualityProblems || entry.blockers > 0 || entry.warnings > 0));
  const sort = filter.sort ?? "newest";
  matched.sort((a, b) => {
    if (sort === "oldest") return Date.parse(a.capturedAt) - Date.parse(b.capturedAt);
    if (sort === "cases-desc") return b.cases - a.cases || b.capturedAt.localeCompare(a.capturedAt);
    if (sort === "problems-desc") return (b.blockers + b.warnings) - (a.blockers + a.warnings) ||
      b.capturedAt.localeCompare(a.capturedAt);
    return Date.parse(b.capturedAt) - Date.parse(a.capturedAt);
  });
  return {
    organizationId, total: entries.length, matched: matched.length, offset, limit,
    entries: matched.slice(offset, offset + limit),
    sources: [...sources.values()].sort((a, b) => a.source.localeCompare(b.source)),
    warnings: ["Snapshot catalog metadata is derived from caller-supplied captures; provenance is not authenticated.",
      "A complete flag is not independent proof of security coverage."],
  };
}
