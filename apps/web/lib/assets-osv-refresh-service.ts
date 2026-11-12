import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import {
  parseRefreshPolicy, planOsvRefresh, buildOsvHistoryDelta,
} from "./assets-osv-refresh-policy";
import type {
  RefreshHistory, RefreshPackageState,
  RefreshPlan, OsvChangeReport,
} from "./assets-osv-refresh-policy";
import type { AssetScope } from "./assets-inventory-service";

export type RefreshReportRequest = {
  policy: ReturnType<typeof parseRefreshPolicy>;
  offset: number;
  limit: number;
  importId: string;
};
export type DeltaReportRequest = {
  previousInspectionId: string;
  currentInspectionId: string;
  offset: number;
  limit: number;
};
type RawHistoryRow = {
  id: string;
  completedAt: Date;
  status: string;
  queryCount: number;
  completedCount: number;
};
type RawQueryRow = {
  queryKey: string;
  inspectionId: string;
  ecosystem: string;
  packageName: string;
  version: string;
  providerStatus: string;
  checkedAt: Date | null;
  observationCount: number;
  possibleIds: unknown;
  providerOnlyIds: unknown;
  unresolvedIds: unknown;
  withdrawnIds: unknown;
};
function inputObject(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new WorkInputError("INVALID", "Expected OSV refresh request.");
  return input as Record<string, unknown>;
}
function integer(value: unknown, name: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid OSV " + name + ".");
  return value;
}
function ids(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return [...new Set(input.filter((value): value is string =>
    typeof value === "string" &&
    value.length <= 120 &&
    /^[A-Za-z0-9][A-Za-z0-9._:+-]{1,119}$/.test(value)))].sort();
}
export function parseRefreshRequest(input: unknown): RefreshReportRequest {
  const raw = inputObject(input);
  if (Object.keys(raw).some(key => ![
    "importId", "policy", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown OSV refresh request field.");
  return {
    importId: parseWorkId(raw.importId, "inventory import ID"),
    policy: parseRefreshPolicy(raw.policy ?? {}),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
  };
}
export function parseDeltaRequest(input: unknown): DeltaReportRequest {
  const raw = inputObject(input);
  if (Object.keys(raw).some(key => ![
    "previousInspectionId", "currentInspectionId", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown OSV history comparison field.");
  const previousInspectionId = parseWorkId(raw.previousInspectionId,
    "previous inspection ID");
  const currentInspectionId = parseWorkId(raw.currentInspectionId,
    "current inspection ID");
  if (previousInspectionId === currentInspectionId)
    throw new WorkInputError("INVALID",
      "Distinct historical inspection IDs are required.");
  return {
    previousInspectionId, currentInspectionId,
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
  };
}
export function queryToRefreshRow(
  query: RawQueryRow,
): RefreshPackageState {
  return {
    ecosystem: query.ecosystem,
    packageName: query.packageName,
    version: query.version,
    providerStatus: query.providerStatus,
    checkedAt: query.checkedAt,
    observationCount: query.observationCount,
    inspectionId: query.inspectionId,
    queryKey: query.queryKey,
    possibleIds: ids(query.possibleIds),
    providerOnlyIds: ids(query.providerOnlyIds),
    unresolvedIds: ids(query.unresolvedIds),
    withdrawnIds: ids(query.withdrawnIds),
  };
}
export function historyToRefreshRow(row: RawHistoryRow): RefreshHistory {
  return {
    inspectionId: row.id,
    completedAt: row.completedAt,
    status: row.status,
    queryCount: row.queryCount,
    completedCount: row.completedCount,
  };
}
export async function inspectOsvRefreshReadiness(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<RefreshPlan> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "OSV refresh planning requires organization inventory access.");
  const request = parseRefreshRequest(input);
  if (!Number.isFinite(now.getTime()))
    throw new WorkInputError("INVALID", "Invalid refresh evaluation time.");
  const inventory = await db.assetInventoryImport.findFirst({
    where: {
      organizationId: scope.organizationId,
      id: request.importId,
    },
    select: { id: true, state: true },
  });
  if (!inventory)
    throw new WorkInputError("MISSING", "Inventory snapshot not found.");
  // This is historical planning. A retired inventory can be inspected, but
  // cannot be submitted to the official API without explicit new authorization.
  const from = new Date(now.getTime() -
    request.policy.historyWindowDays * 86400000);
  const utcDayStart = new Date(Date.UTC(now.getUTCFullYear(),
    now.getUTCMonth(), now.getUTCDate()));
  const [historical, recentQueries] = await db.$transaction([
    db.assetOsvInspection.findMany({
      where: {
        organizationId: scope.organizationId,
        inventoryImportId: request.importId,
        completedAt: { gte: from, lte: now },
      },
      select: {
        id: true, completedAt: true, status: true,
        queryCount: true, completedCount: true,
        queries: {
          select: {
            queryKey: true, inspectionId: true,
            ecosystem: true, packageName: true, version: true,
            providerStatus: true, checkedAt: true,
            observationCount: true,
            possibleIds: true, providerOnlyIds: true,
            unresolvedIds: true, withdrawnIds: true,
          },
          orderBy: { recordedAt: "desc" },
        },
      },
      orderBy: { completedAt: "desc" }, take: 1000,
    }),
    db.assetOsvInspection.findMany({
      where: {
        organizationId: scope.organizationId,
        completedAt: { gte: utcDayStart, lte: now },
      },
      select: {
        id: true, completedAt: true, status: true,
        queryCount: true, completedCount: true,
      },
      take: 10000,
    }),
  ]);
  if (historical.length >= 1000 || recentQueries.length >= 10000)
    throw new WorkInputError("CONFLICT",
      "OSV refresh history exceeds bounded inspection capacity.");
  const rows = historical.flatMap(item =>
    item.queries.map(queryToRefreshRow));
  const total = rows.length;
  if (total > 10000)
    throw new WorkInputError("CONFLICT",
      "OSV package query history exceeds bounded comparison capacity.");
  const report = planOsvRefresh(scope.organizationId, {
    policy: request.policy,
    history: recentQueries.map(historyToRefreshRow),
    packages: rows, now,
    offset: request.offset, limit: request.limit,
  });
  if (inventory.state !== "COMMITTED") {
    report.selected = [];
    report.selectedCount = 0;
    report.excludedDueToBudget = report.dueCount;
    report.warnings.push(
      "Inventory is retired: no refresh request can be executed.");
  }
  return report;
}
function reportStatus(report: unknown): boolean {
  if (!report || typeof report !== "object" || Array.isArray(report))
    return false;
  const entry = report as Record<string, unknown>;
  return entry.schema === "cyberpilot.assets.osv.official.inspection.v1" &&
    entry.dryRun === false && entry.status === "COMPLETE" &&
    entry.coverage === "DECLARED_NOT_VERIFIED";
}
export async function inspectOsvHistoryDelta(
  scope: AssetScope, input: unknown,
): Promise<OsvChangeReport> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "OSV history comparison requires inventory access.");
  const command = parseDeltaRequest(input);
  const inspections = await db.assetOsvInspection.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: [command.previousInspectionId,
        command.currentInspectionId] },
    },
    include: {
      queries: {
        select: {
          queryKey: true, inspectionId: true,
          ecosystem: true, packageName: true, version: true,
          providerStatus: true, checkedAt: true,
          observationCount: true,
          possibleIds: true, providerOnlyIds: true,
          unresolvedIds: true, withdrawnIds: true,
        },
        orderBy: { queryKey: "asc" },
        take: 101,
      },
    },
  });
  if (inspections.length !== 2)
    throw new WorkInputError("MISSING",
      "At least one OSV inspection is not accessible.");
  const previous = inspections.find(row =>
    row.id === command.previousInspectionId)!;
  const current = inspections.find(row =>
    row.id === command.currentInspectionId)!;
  if (previous.inventoryImportId !== current.inventoryImportId)
    throw new WorkInputError("INVALID",
      "Only OSV inspections of the same inventory can be compared.");
  if (previous.completedAt > current.completedAt)
    throw new WorkInputError("INVALID",
      "Previous inspection must not be newer than current inspection.");
  if (previous.queryCount > 100 || current.queryCount > 100 ||
      previous.queries.length !== previous.queryCount ||
      current.queries.length !== current.queryCount)
    throw new WorkInputError("CONFLICT",
      "Persisted OSV inspection query coverage is inconsistent.");
  return buildOsvHistoryDelta(
    scope.organizationId, previous.id, current.id,
    previous.queries.map(queryToRefreshRow),
    current.queries.map(queryToRefreshRow),
    reportStatus(previous.report), reportStatus(current.report),
    command.offset, command.limit,
  );
}
