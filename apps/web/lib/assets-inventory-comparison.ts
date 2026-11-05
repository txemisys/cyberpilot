import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";

export type AssetComparisonQuery = {
  previousImportId: string;
  currentImportId: string;
  offset: number;
  limit: number;
  category?: AssetDifferenceCategory;
  includeUnchanged: boolean;
};
export type AssetDifferenceCategory =
  | "NEW_ASSET" | "MISSING_FROM_EXPORT" | "NEW_PRODUCT"
  | "PRODUCT_NOT_IN_EXPORT" | "OS_CHANGED" | "VERSION_CHANGED"
  | "PLATFORM_CHANGED" | "ADVISORY_CHANGED" | "OBSERVATION_UPDATED"
  | "UNCHANGED";
export type AssetObservation = {
  externalId: string;
  normalizedProductKey: string;
  platform: string;
  osName: string;
  osVersion: string | null;
  softwareName: string;
  softwareVersion: string | null;
  versionStatus: string;
  freshnessStatus: string;
  advisoryStatus: string;
  advisoryIds: unknown;
  observedAt: Date;
  sourceRow: number;
};
export type AssetComparisonImport = {
  id: string;
  state: "COMMITTED" | "RETIRED";
  sourceLabel: string;
  importedCount: number;
  declaredCount: number;
  duplicateCount: number;
  createdAt: Date;
};
export type AssetComparisonDifference = {
  key: string;
  externalId: string;
  productKey: string;
  category: AssetDifferenceCategory;
  significant: boolean;
  previousValue: string | null;
  currentValue: string | null;
  previousObservedAt: string | null;
  currentObservedAt: string | null;
  previousRow: number | null;
  currentRow: number | null;
  confidence: "DECLARED_COMPARISON_ONLY";
  explanations: string[];
  fingerprint: string;
};
export type AssetComparisonSummary = {
  inspectedPrevious: number;
  inspectedCurrent: number;
  uniqueAssetsPrevious: number;
  uniqueAssetsCurrent: number;
  unchanged: number;
  changed: number;
  newAssets: number;
  missingFromExport: number;
  newProducts: number;
  productsNotInExport: number;
  osChanges: number;
  versionChanges: number;
  platformChanges: number;
  advisoryChanges: number;
  observationUpdates: number;
  perCategory: Record<AssetDifferenceCategory, number>;
};
export type AssetComparisonReport = {
  schema: "cyberpilot.assets.csv.comparison.v1";
  organizationId: string;
  previousImport: AssetComparisonImport;
  currentImport: AssetComparisonImport;
  generatedAt: string;
  offset: number;
  limit: number;
  totalDifferences: number;
  hasMore: boolean;
  complete: boolean;
  coverage: "DECLARED_SCOPE_UNKNOWN";
  summary: AssetComparisonSummary;
  rows: AssetComparisonDifference[];
  digest: string;
  warnings: string[];
};
const categories: AssetDifferenceCategory[] = [
  "NEW_ASSET", "MISSING_FROM_EXPORT", "NEW_PRODUCT",
  "PRODUCT_NOT_IN_EXPORT", "OS_CHANGED", "VERSION_CHANGED",
  "PLATFORM_CHANGED", "ADVISORY_CHANGED",
  "OBSERVATION_UPDATED", "UNCHANGED",
];
const categoryOrder = new Map(categories.map((category, position) =>
  [category, position]));
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected inventory comparison request.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
    value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid inventory comparison " + label + ".");
  return value;
}
export function parseAssetComparisonQuery(value: unknown): AssetComparisonQuery {
  const raw = record(value);
  if (Object.keys(raw).some(key => ![
    "previousImportId", "currentImportId", "offset", "limit",
    "category", "includeUnchanged",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown inventory comparison parameter.");
  const previousImportId = parseWorkId(raw.previousImportId, "previous import ID");
  const currentImportId = parseWorkId(raw.currentImportId, "current import ID");
  if (previousImportId === currentImportId)
    throw new WorkInputError("INVALID", "Comparison requires two different imports.");
  if (raw.category !== undefined && !categories.includes(
    raw.category as AssetDifferenceCategory))
    throw new WorkInputError("INVALID", "Unknown inventory comparison category.");
  if (raw.includeUnchanged !== undefined &&
      typeof raw.includeUnchanged !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeUnchanged.");
  return {
    previousImportId, currentImportId,
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    includeUnchanged: raw.includeUnchanged === true,
    ...(raw.category === undefined ? {} : {
      category: raw.category as AssetDifferenceCategory,
    }),
  };
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function advisoryIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((x): x is string =>
    typeof x === "string" && /^CVE-\d{4}-\d{4,}$/.test(x)))].sort();
}
function identity(value: AssetObservation): string {
  return value.externalId + "\u0000" + value.normalizedProductKey;
}
function uniqueAssets(rows: AssetObservation[]) {
  return new Set(rows.map(row => row.externalId)).size;
}
function csvValue(row: AssetObservation | null) {
  if (!row) return null;
  return [
    row.platform, row.osName, row.osVersion ?? "UNKNOWN",
    row.softwareName || "NO_PRODUCT",
    row.softwareVersion ?? "UNKNOWN",
    row.versionStatus, row.advisoryStatus,
  ].join(" / ");
}
function codes(previous: AssetObservation | null,
  current: AssetObservation | null,
  previousAssets: Set<string>, currentAssets: Set<string>,
): AssetDifferenceCategory[] {
  if (!previous && current)
    return [previousAssets.has(current.externalId) ?
      "NEW_PRODUCT" : "NEW_ASSET"];
  if (previous && !current)
    return [currentAssets.has(previous.externalId) ?
      "PRODUCT_NOT_IN_EXPORT" : "MISSING_FROM_EXPORT"];
  if (!previous || !current) return [];
  const changed: AssetDifferenceCategory[] = [];
  if (previous.platform !== current.platform)
    changed.push("PLATFORM_CHANGED");
  if (previous.osName !== current.osName ||
      previous.osVersion !== current.osVersion)
    changed.push("OS_CHANGED");
  if (previous.softwareVersion !== current.softwareVersion ||
      previous.versionStatus !== current.versionStatus)
    changed.push("VERSION_CHANGED");
  if (previous.advisoryStatus !== current.advisoryStatus ||
      JSON.stringify(advisoryIds(previous.advisoryIds)) !==
        JSON.stringify(advisoryIds(current.advisoryIds)))
    changed.push("ADVISORY_CHANGED");
  if (previous.observedAt.getTime() !== current.observedAt.getTime() &&
      changed.length === 0)
    changed.push("OBSERVATION_UPDATED");
  return changed.length ? changed : ["UNCHANGED"];
}
function explanation(category: AssetDifferenceCategory): string {
  const messages: Record<AssetDifferenceCategory, string> = {
    NEW_ASSET: "Identifier first appears in the selected later CSV; not proof of a newly deployed device.",
    MISSING_FROM_EXPORT: "Identifier absent from later CSV; not proof of device removal.",
    NEW_PRODUCT: "Additional product reported for an identifier present in both exports.",
    PRODUCT_NOT_IN_EXPORT: "Product no longer listed for an identifier; not evidence it was uninstalled.",
    OS_CHANGED: "Declared OS name or version changed between submissions.",
    VERSION_CHANGED: "Declared software version or version confidence changed.",
    PLATFORM_CHANGED: "Declared device platform changed.",
    ADVISORY_CHANGED: "Advisory association changed between declared snapshots; feeds may differ.",
    OBSERVATION_UPDATED: "Observation time changed without a relevant product or OS value change.",
    UNCHANGED: "Declared product details match; this does not verify current security.",
  };
  return messages[category];
}
export function compareAssetObservations(
  previous: AssetObservation[],
  current: AssetObservation[],
): AssetComparisonDifference[] {
  const older = new Map(previous.map(row => [identity(row), row]));
  const newer = new Map(current.map(row => [identity(row), row]));
  const previousAssets = new Set(previous.map(row => row.externalId));
  const currentAssets = new Set(current.map(row => row.externalId));
  const keys = [...new Set([...older.keys(), ...newer.keys()])].sort();
  const differences: AssetComparisonDifference[] = [];
  for (const key of keys) {
    const oldRow = older.get(key) ?? null;
    const newRow = newer.get(key) ?? null;
    for (const category of codes(oldRow, newRow, previousAssets, currentAssets)) {
      const representative = newRow ?? oldRow!;
      const canonical = {
        key: key + ":" + category,
        externalId: representative.externalId,
        productKey: representative.normalizedProductKey,
        category,
        significant: category !== "UNCHANGED" &&
          category !== "OBSERVATION_UPDATED",
        previousValue: csvValue(oldRow), currentValue: csvValue(newRow),
        previousObservedAt: oldRow?.observedAt.toISOString() ?? null,
        currentObservedAt: newRow?.observedAt.toISOString() ?? null,
        previousRow: oldRow?.sourceRow ?? null,
        currentRow: newRow?.sourceRow ?? null,
        confidence: "DECLARED_COMPARISON_ONLY" as const,
        explanations: [explanation(category)],
      };
      differences.push({ ...canonical, fingerprint: hash(canonical) });
    }
  }
  return differences.sort((a, b) =>
    (categoryOrder.get(a.category) ?? 99) -
      (categoryOrder.get(b.category) ?? 99) ||
    a.externalId.localeCompare(b.externalId) ||
    a.productKey.localeCompare(b.productKey));
}
export function summarizeAssetComparison(
  previous: AssetObservation[], current: AssetObservation[],
  rows: AssetComparisonDifference[],
): AssetComparisonSummary {
  const perCategory = Object.fromEntries(
    categories.map(category => [category, 0]),
  ) as Record<AssetDifferenceCategory, number>;
  for (const row of rows) perCategory[row.category]++;
  return {
    inspectedPrevious: previous.length,
    inspectedCurrent: current.length,
    uniqueAssetsPrevious: uniqueAssets(previous),
    uniqueAssetsCurrent: uniqueAssets(current),
    unchanged: perCategory.UNCHANGED,
    changed: rows.filter(row => row.significant).length,
    newAssets: perCategory.NEW_ASSET,
    missingFromExport: perCategory.MISSING_FROM_EXPORT,
    newProducts: perCategory.NEW_PRODUCT,
    productsNotInExport: perCategory.PRODUCT_NOT_IN_EXPORT,
    osChanges: perCategory.OS_CHANGED,
    versionChanges: perCategory.VERSION_CHANGED,
    platformChanges: perCategory.PLATFORM_CHANGED,
    advisoryChanges: perCategory.ADVISORY_CHANGED,
    observationUpdates: perCategory.OBSERVATION_UPDATED,
    perCategory,
  };
}
export function buildAssetComparisonReport(
  organizationId: string, previousImport: AssetComparisonImport,
  currentImport: AssetComparisonImport, previous: AssetObservation[],
  current: AssetObservation[], query: AssetComparisonQuery, now: Date,
): AssetComparisonReport {
  const all = compareAssetObservations(previous, current);
  const summary = summarizeAssetComparison(previous, current, all);
  const filtered = all.filter(row =>
    (query.includeUnchanged || row.category !== "UNCHANGED") &&
    (!query.category || row.category === query.category));
  const rows = filtered.slice(query.offset, query.offset + query.limit);
  const complete = query.offset === 0 && rows.length === filtered.length;
  const canonical = {
    schema: "cyberpilot.assets.csv.comparison.v1" as const,
    organizationId, previousImport, currentImport,
    generatedAt: now.toISOString(),
    offset: query.offset, limit: query.limit,
    totalDifferences: filtered.length,
    hasMore: query.offset + rows.length < filtered.length,
    complete,
    coverage: "DECLARED_SCOPE_UNKNOWN" as const,
    summary, rows,
  };
  return {
    ...canonical, digest: hash(canonical),
    warnings: [
      "Both exports are customer-declared; their device coverage is not independently verified.",
      "Missing rows may reflect a partial export, changed identifiers or scope, not actual device removal.",
      "Product and OS versions are declared values and do not establish patch compliance.",
      "Advisory association changes may reflect different customer-supplied feed versions.",
      "Category counts can overlap because one row may change in several dimensions.",
      "The summary covers both complete selected snapshots, while rows are paginated.",
      "No external systems are contacted and CyberScore is not modified.",
    ],
  };
}
export async function readAssetComparison(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<AssetComparisonReport> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Inventory comparison access denied.");
  const query = parseAssetComparisonQuery(input);
  const imports = await db.assetInventoryImport.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: [query.previousImportId, query.currentImportId] },
    },
    select: {
      id: true, state: true, sourceLabel: true,
      importedCount: true, declaredCount: true,
      duplicateCount: true, createdAt: true,
    },
  });
  if (imports.length !== 2)
    throw new WorkInputError("MISSING", "One or both inventory snapshots were not found.");
  const previousImport = imports.find(x => x.id === query.previousImportId)!;
  const currentImport = imports.find(x => x.id === query.currentImportId)!;
  if (previousImport.createdAt > currentImport.createdAt)
    throw new WorkInputError("INVALID",
      "Previous snapshot must not be newer than current snapshot.");
  if (previousImport.importedCount > 10000 || currentImport.importedCount > 10000)
    throw new WorkInputError("INVALID", "Snapshot exceeds safe comparison limit.");
  const [previous, current] = await db.$transaction([
    db.assetInventoryDevice.findMany({
      where: {
        organizationId: scope.organizationId, importId: previousImport.id,
      },
      select: {
        externalId: true, normalizedProductKey: true,
        platform: true, osName: true, osVersion: true,
        softwareName: true, softwareVersion: true,
        versionStatus: true, freshnessStatus: true,
        advisoryStatus: true, advisoryIds: true,
        observedAt: true, sourceRow: true,
      },
      take: 10001,
    }),
    db.assetInventoryDevice.findMany({
      where: {
        organizationId: scope.organizationId, importId: currentImport.id,
      },
      select: {
        externalId: true, normalizedProductKey: true,
        platform: true, osName: true, osVersion: true,
        softwareName: true, softwareVersion: true,
        versionStatus: true, freshnessStatus: true,
        advisoryStatus: true, advisoryIds: true,
        observedAt: true, sourceRow: true,
      },
      take: 10001,
    }),
  ]);
  if (previous.length > 10000 || current.length > 10000 ||
      previous.length !== previousImport.importedCount ||
      current.length !== currentImport.importedCount)
    throw new WorkInputError("CONFLICT",
      "Snapshot row coverage is incomplete; comparison refused.");
  return buildAssetComparisonReport(scope.organizationId,
    previousImport, currentImport, previous, current, query, now);
}
