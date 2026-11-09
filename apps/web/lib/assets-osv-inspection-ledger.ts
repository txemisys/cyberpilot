import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { parseOfficialOsvInspection, inspectOfficialOsv } from "./assets-osv-official-service";
import type {
  OfficialOsvInspectionInput, OfficialOsvInspectionReport,
  OfficialOsvPackageResult, OfficialOsvFetchDependencies,
} from "./assets-osv-official-service";
import type { AssetScope } from "./assets-inventory-service";

export type OsvLedgerCommand = {
  requestKey: string;
  inspection: OfficialOsvInspectionInput;
};
export type OsvLedgerQuery = {
  importId?: string;
  inspectionId?: string;
  status?: string;
  offset: number;
  limit: number;
};
export type OsvLedgerRow = {
  id: string;
  inventoryImportId: string;
  requestKey: string;
  status: string;
  provider: string;
  coverage: string;
  requestDigest: string;
  reportDigest: string;
  queryCount: number;
  completedCount: number;
  possibleCount: number;
  providerOnlyCount: number;
  completedAt: Date;
  createdAt: Date;
};
export type OsvLedgerQueryRow = {
  id: string;
  inspectionId: string;
  queryKey: string;
  ecosystem: string;
  packageName: string;
  version: string;
  providerStatus: string;
  providerDigest: string | null;
  checkedAt: Date | null;
  possibleIds: unknown;
  providerOnlyIds: unknown;
  withdrawnIds: unknown;
  unresolvedIds: unknown;
  observationCount: number;
  pageCount: number;
  recordedAt: Date;
};
export type OsvLedgerPage = {
  schema: "cyberpilot.assets.osv.inspections.v1";
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  inspections: OsvLedgerRow[];
  warnings: string[];
};
export type OsvLedgerDetail = {
  schema: "cyberpilot.assets.osv.inspection.detail.v1";
  inspection: OsvLedgerRow;
  report: OfficialOsvInspectionReport;
  recordedQueries: OsvLedgerQueryRow[];
  persistedReportDigest: string;
  checkedAt: Date;
  warnings: string[];
};
export type OsvLedgerCommit = {
  schema: "cyberpilot.assets.osv.inspection.commit.v1";
  inspectionId: string;
  replayed: boolean;
  requestDigest: string;
  reportDigest: string;
  status: string;
  queryCount: number;
  report: OfficialOsvInspectionReport;
  warnings: string[];
};
function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new WorkInputError("INVALID", "Expected OSV ledger object.");
  return input as Record<string, unknown>;
}
function allowed(input: Record<string, unknown>, accepted: string[]) {
  if (Object.keys(input).some(key => !accepted.includes(key)))
    throw new WorkInputError("INVALID", "Unknown OSV ledger property.");
}
function integer(input: unknown, label: string, low: number, high: number) {
  if (typeof input !== "number" || !Number.isSafeInteger(input) ||
      input < low || input > high)
    throw new WorkInputError("INVALID", "Invalid OSV ledger " + label + ".");
  return input;
}
function short(input: unknown, label: string, max = 150) {
  if (typeof input !== "string" || !input.trim() ||
      input.length > max || /[\u0000-\u001f\u007f]/.test(input))
    throw new WorkInputError("INVALID", "Invalid OSV ledger " + label + ".");
  return input.trim();
}
function sha(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
export function parseOsvLedgerCommand(input: unknown): OsvLedgerCommand {
  const raw = object(input);
  allowed(raw, ["requestKey", "inspection"]);
  const requestKey = short(raw.requestKey, "request key");
  if (requestKey.length < 12)
    throw new WorkInputError("INVALID", "OSV request key is too short.");
  const inspection = parseOfficialOsvInspection(raw.inspection);
  if (inspection.dryRun)
    throw new WorkInputError("INVALID",
      "A preview cannot be persisted as a provider inspection.");
  return { requestKey, inspection };
}
export function parseOsvLedgerQuery(input: unknown): OsvLedgerQuery {
  const raw = object(input);
  allowed(raw, ["importId", "inspectionId", "status", "offset", "limit"]);
  const status = raw.status === undefined ? undefined :
    short(raw.status, "status", 30);
  if (status && !["COMPLETE", "PARTIAL", "INCOMPLETE", "ERROR"].includes(status))
    throw new WorkInputError("INVALID", "Unknown OSV inspection status.");
  return {
    ...(raw.importId === undefined ? {} : {
      importId: parseWorkId(raw.importId, "import ID"),
    }),
    ...(raw.inspectionId === undefined ? {} : {
      inspectionId: parseWorkId(raw.inspectionId, "inspection ID"),
    }),
    ...(status ? { status } : {}),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
  };
}
export function osvInspectionFingerprint(
  scope: Pick<AssetScope, "organizationId">,
  command: OsvLedgerCommand,
): string {
  const bindings = [...command.inspection.packageBindings]
    .sort((a, b) => a.inventoryProduct.localeCompare(b.inventoryProduct) ||
      a.ecosystem.localeCompare(b.ecosystem) ||
      a.packageName.localeCompare(b.packageName));
  return sha({
    schema: "cyberpilot.assets.osv.inspection.command.v1",
    organizationId: scope.organizationId,
    requestKey: command.requestKey,
    importId: command.inspection.importId,
    packageBindings: bindings,
    limitPackages: command.inspection.limitPackages,
    maxPagesPerPackage: command.inspection.maxPagesPerPackage,
    maxRecordsPerPackage: command.inspection.maxRecordsPerPackage,
    maxAgeMinutes: command.inspection.maxAgeMinutes,
    provider: "OSV_DEV_API",
  });
}
export function osvInspectionLedgerKey(
  result: Pick<OfficialOsvPackageResult,
  "ecosystem" | "name" | "version" | "key">,
): string {
  return sha([result.ecosystem, result.name, result.version, result.key]);
}
export function assertLedgerReport(
  scope: AssetScope,
  command: OsvLedgerCommand,
  report: OfficialOsvInspectionReport,
): void {
  if (report.schema !== "cyberpilot.assets.osv.official.inspection.v1" ||
      report.organizationId !== scope.organizationId ||
      report.importId !== command.inspection.importId ||
      report.providerOrigin !== "OSV_DEV_HTTPS_API" ||
      report.inventoryOrigin !== "CUSTOMER_DECLARED_CSV" ||
      report.dryRun || report.status === "PREVIEW")
    throw new WorkInputError("CONFLICT",
      "Provider report provenance conflicts with authorized request.");
  if (report.results.length > command.inspection.limitPackages ||
      report.results.length !== report.queriesAttempted ||
      report.queriesCompleted > report.queriesAttempted ||
      new Set(report.results.map(result => result.key)).size !== report.results.length)
    throw new WorkInputError("CONFLICT",
      "Provider query counts or identities are inconsistent.");
  if (report.plan.inventoryRows < 1 ||
      report.plan.selectedPackages !== report.results.length ||
      report.plan.importId !== command.inspection.importId)
    throw new WorkInputError("CONFLICT",
      "Provider report is incomplete or misattributed.");
  if (report.results.some(result =>
    !report.plan.work.some(work => work.key === result.key &&
      work.ecosystem === result.ecosystem &&
      work.name === result.name &&
      work.version === result.version)))
    throw new WorkInputError("CONFLICT",
      "Provider result does not belong to the authorized package plan.");
}
function warnReplay(): string[] {
  return [
    "Idempotent replay returns the original persisted report; no OSV API query ran.",
    "Historical provider status and source version can be stale.",
    "The ledger is not evidence of verified endpoint exploitability.",
  ];
}
export function replayOsvLedger(
  scope: AssetScope,
  command: OsvLedgerCommand,
  existing: {
    id: string;
    requestDigest: string;
    reportDigest: string;
    status: string;
    report: unknown;
    queryCount: number;
  },
): OsvLedgerCommit {
  const fingerprint = osvInspectionFingerprint(scope, command);
  if (existing.requestDigest !== fingerprint)
    throw new WorkInputError("CONFLICT",
      "OSV request key was already used with different parameters.");
  const report = existing.report as OfficialOsvInspectionReport;
  if (!report || typeof report !== "object" ||
      report.reportDigest !== existing.reportDigest ||
      report.organizationId !== scope.organizationId)
    throw new WorkInputError("CONFLICT",
      "Stored inspection report metadata is inconsistent.");
  return {
    schema: "cyberpilot.assets.osv.inspection.commit.v1",
    inspectionId: existing.id, replayed: true,
    requestDigest: existing.requestDigest,
    reportDigest: existing.reportDigest,
    status: existing.status, queryCount: existing.queryCount,
    report, warnings: warnReplay(),
  };
}
export function buildOsvLedgerCommit(
  scope: AssetScope, command: OsvLedgerCommand,
  report: OfficialOsvInspectionReport, inspectionId: string,
): OsvLedgerCommit {
  assertLedgerReport(scope, command, report);
  return {
    schema: "cyberpilot.assets.osv.inspection.commit.v1",
    inspectionId, replayed: false,
    requestDigest: osvInspectionFingerprint(scope, command),
    reportDigest: report.reportDigest,
    status: report.status, queryCount: report.results.length,
    report, warnings: [
      "Provider query results are stored as immutable inspection snapshots.",
      "No CyberScore, security finding, or remediation status is modified.",
      "A provider response is not equivalent to a verified endpoint observation.",
    ],
  };
}
function parseStoredReport(value: unknown): OfficialOsvInspectionReport {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("CONFLICT", "Stored OSV report is invalid.");
  const report = value as OfficialOsvInspectionReport;
  if (report.schema !== "cyberpilot.assets.osv.official.inspection.v1" ||
      !Array.isArray(report.results) || !report.reportDigest ||
      typeof report.organizationId !== "string")
    throw new WorkInputError("CONFLICT", "Stored OSV report shape is invalid.");
  return report;
}
export async function persistOsvInspection(
  scope: AssetScope, input: unknown,
  dependencies: OfficialOsvFetchDependencies = {},
): Promise<OsvLedgerCommit> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only organization administrators may create OSV inspection records.");
  const command = parseOsvLedgerCommand(input);
  const fingerprint = osvInspectionFingerprint(scope, command);
  const unique = {
    organizationId_requestKey: {
      organizationId: scope.organizationId,
      requestKey: command.requestKey,
    },
  };
  const existing = await db.assetOsvInspection.findUnique({ where: unique });
  if (existing) return replayOsvLedger(scope, command, existing);
  // Provider calls occur outside the transaction. A long remote request
  // never holds a database lock, and its results remain read-only until commit.
  const report = await inspectOfficialOsv(scope, command.inspection, {
    ...dependencies,
    quotaRequestKey: "osv-ledger-" + command.requestKey,
  });
  assertLedgerReport(scope, command, report);
  const last = await db.assetInventoryImport.findFirst({
    where: {
      organizationId: scope.organizationId,
      id: command.inspection.importId,
      state: "COMMITTED",
    },
    select: { id: true },
  });
  if (!last)
    throw new WorkInputError("CONFLICT",
      "Inventory was retired before the OSV report could be committed.");
  try {
    const created = await db.$transaction(async tx => {
      const snapshot = await tx.assetInventoryImport.findFirst({
        where: {
          organizationId: scope.organizationId,
          id: command.inspection.importId,
          state: "COMMITTED",
        },
        select: { id: true },
      });
      if (!snapshot)
        throw new WorkInputError("CONFLICT",
          "Inventory is no longer active.");
      const inspection = await tx.assetOsvInspection.create({
        data: {
          organizationId: scope.organizationId,
          inventoryImportId: command.inspection.importId,
          actorUserId: scope.userId,
          requestKey: command.requestKey,
          requestDigest: fingerprint,
          reportDigest: report.reportDigest,
          status: report.status,
          report: JSON.parse(JSON.stringify(report)),
          queryCount: report.queriesAttempted,
          completedCount: report.queriesCompleted,
          possibleCount: report.totalPossibleAssociations,
          providerOnlyCount: report.totalProviderOnlyAssociations,
          completedAt: new Date(report.generatedAt),
        },
      });
      if (report.results.length) {
        await tx.assetOsvQueryRecord.createMany({
          data: report.results.map(row => ({
            organizationId: scope.organizationId,
            inspectionId: inspection.id,
            queryKey: osvInspectionLedgerKey(row),
            ecosystem: row.ecosystem,
            packageName: row.name,
            version: row.version,
            providerStatus: row.status,
            providerDigest: row.digest,
            checkedAt: row.checkedAt ? new Date(row.checkedAt) : null,
            possibleIds: row.possibleIds,
            providerOnlyIds: row.providerOnlyIds,
            withdrawnIds: row.withdrawnIds,
            unresolvedIds: row.unresolvedIds,
            observationCount: row.observationCount,
            pageCount: row.queriedPages,
          })),
        });
      }
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER", actorUserId: scope.userId,
          action: "assets.osv.inspection.committed",
          resourceType: "AssetOsvInspection",
          resourceId: inspection.id,
          metadata: {
            schema: "cyberpilot.assets.osv.inspection.audit.v1",
            inventoryImportId: command.inspection.importId,
            requestDigest: fingerprint,
            reportDigest: report.reportDigest,
            status: report.status,
            queriedPackages: report.queriesAttempted,
            coverage: report.coverage,
            source: report.providerOrigin,
          },
        },
      });
      return inspection;
    });
    return buildOsvLedgerCommit(scope, command, report, created.id);
  } catch (cause) {
    // A concurrent identical request can commit before this transaction;
    // return that stored result instead of misreporting the duplicate as 500.
    if (cause && typeof cause === "object" &&
        "code" in cause && cause.code === "P2002") {
      const raced = await db.assetOsvInspection.findUnique({ where: unique });
      if (raced) return replayOsvLedger(scope, command, raced);
    }
    throw cause;
  }
}
export async function listOsvInspections(
  scope: AssetScope, input: unknown,
): Promise<OsvLedgerPage> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "OSV inspection access denied.");
  const query = parseOsvLedgerQuery(input);
  const where = {
    organizationId: scope.organizationId,
    ...(query.importId ? { inventoryImportId: query.importId } : {}),
    ...(query.inspectionId ? { id: query.inspectionId } : {}),
    ...(query.status ? { status: query.status } : {}),
  };
  const [total, inspections] = await db.$transaction([
    db.assetOsvInspection.count({ where }),
    db.assetOsvInspection.findMany({
      where, orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, inventoryImportId: true, requestKey: true,
        status: true, provider: true, coverage: true,
        requestDigest: true, reportDigest: true,
        queryCount: true, completedCount: true,
        possibleCount: true, providerOnlyCount: true,
        completedAt: true, createdAt: true,
      },
    }),
  ]);
  return {
    schema: "cyberpilot.assets.osv.inspections.v1",
    total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + inspections.length < total,
    inspections,
    warnings: [
      "Historical OSV assessments are provider reports, not endpoint vulnerability verification.",
      "A previous COMPLETE result cannot establish current security.",
      "Some OSV query results can reflect upstream approximate version matching.",
    ],
  };
}
export async function readOsvInspection(
  scope: AssetScope, input: unknown,
): Promise<OsvLedgerDetail> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "OSV inspection access denied.");
  const query = parseOsvLedgerQuery(input);
  if (!query.inspectionId)
    throw new WorkInputError("INVALID", "Inspection ID is required.");
  const found = await db.assetOsvInspection.findFirst({
    where: {
      organizationId: scope.organizationId,
      id: query.inspectionId,
      ...(query.importId ? { inventoryImportId: query.importId } : {}),
    },
    include: {
      queries: {
        orderBy: [{ ecosystem: "asc" }, { packageName: "asc" },
          { version: "asc" }],
        take: 100,
      },
    },
  });
  if (!found)
    throw new WorkInputError("MISSING", "OSV inspection not found.");
  const report = parseStoredReport(found.report);
  if (report.reportDigest !== found.reportDigest ||
      report.organizationId !== scope.organizationId ||
      report.importId !== found.inventoryImportId ||
      found.queries.length !== found.queryCount)
    throw new WorkInputError("CONFLICT",
      "Stored OSV inspection failed consistency verification.");
  const summary: OsvLedgerRow = {
    id: found.id, inventoryImportId: found.inventoryImportId,
    requestKey: found.requestKey, status: found.status,
    provider: found.provider, coverage: found.coverage,
    requestDigest: found.requestDigest,
    reportDigest: found.reportDigest,
    queryCount: found.queryCount, completedCount: found.completedCount,
    possibleCount: found.possibleCount,
    providerOnlyCount: found.providerOnlyCount,
    completedAt: found.completedAt, createdAt: found.createdAt,
  };
  return {
    schema: "cyberpilot.assets.osv.inspection.detail.v1",
    inspection: summary, report,
    recordedQueries: found.queries,
    persistedReportDigest: found.reportDigest,
    checkedAt: found.completedAt,
    warnings: [
      "This is a historical immutable provider query record.",
      "It is not evidence of live endpoint exposure or successful remediation.",
      "The inventory snapshot and package mappings were customer-declared.",
    ],
  };
}
