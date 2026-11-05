import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { parsePackageBindings } from "./assets-osv-correlation";
import type { PackageBinding } from "./assets-osv-correlation";
import {
  queryOfficialOsv, validateLiveOsvRequest,
} from "./assets-osv-official-client";
import type {
  LiveOsvQueryResult, LiveOsvClientOptions,
} from "./assets-osv-official-client";
import type { AssetScope } from "./assets-inventory-service";

export type OfficialOsvInspectionInput = {
  importId: string;
  packageBindings: PackageBinding[];
  limitPackages: number;
  maxPagesPerPackage: number;
  maxRecordsPerPackage: number;
  maxAgeMinutes: number;
  dryRun: boolean;
};
export type OfficialOsvPackageWork = {
  key: string;
  ecosystem: string;
  name: string;
  version: string;
  expectedPurl: string | null;
  observationCount: number;
  identifiers: string[];
};
export type OfficialOsvPackageResult = {
  key: string;
  ecosystem: string;
  name: string;
  version: string;
  observationCount: number;
  status: string;
  checkedAt: string | null;
  digest: string | null;
  possibleIds: string[];
  providerOnlyIds: string[];
  withdrawnIds: string[];
  unresolvedIds: string[];
  queriedPages: number;
  warnings: string[];
};
export type OfficialOsvPlan = {
  importId: string;
  inventoryRows: number;
  mappedRows: number;
  unmappedRows: number;
  invalidVersionRows: number;
  mappedPackages: number;
  actionablePackages: number;
  selectedPackages: number;
  skippedPackages: number;
  allRowsAccountedFor: boolean;
  work: OfficialOsvPackageWork[];
  warnings: string[];
};
export type OfficialOsvInspectionReport = {
  schema: "cyberpilot.assets.osv.official.inspection.v1";
  organizationId: string;
  importId: string;
  inventoryOrigin: "CUSTOMER_DECLARED_CSV";
  providerOrigin: "OSV_DEV_HTTPS_API";
  generatedAt: string;
  dryRun: boolean;
  status: "PREVIEW" | "COMPLETE" | "PARTIAL" | "INCOMPLETE" | "ERROR";
  coverage: "DECLARED_NOT_VERIFIED";
  plan: OfficialOsvPlan;
  results: OfficialOsvPackageResult[];
  queriesAttempted: number;
  queriesCompleted: number;
  totalPossibleAssociations: number;
  totalProviderOnlyAssociations: number;
  totalUnresolved: number;
  totalWithdrawn: number;
  reportDigest: string;
  warnings: string[];
};
type SnapshotRow = {
  externalId: string;
  softwareName: string;
  softwareVersion: string | null;
  versionStatus: string;
  normalizedProductKey: string;
};
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected official OSV request object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, min: number, max: number, label: string) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid official OSV " + label + ".");
  return value;
}
export function parseOfficialOsvInspection(
  input: unknown,
): OfficialOsvInspectionInput {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "importId", "packageBindings", "limitPackages", "maxPagesPerPackage",
    "maxRecordsPerPackage", "maxAgeMinutes", "dryRun",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unexpected official OSV request field.");
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    throw new WorkInputError("INVALID", "Invalid official OSV preview flag.");
  if (!Array.isArray(raw.packageBindings))
    throw new WorkInputError("INVALID", "Explicit package bindings are required.");
  return {
    importId: parseWorkId(raw.importId, "import ID"),
    packageBindings: parsePackageBindings(raw.packageBindings),
    limitPackages: integer(raw.limitPackages ?? 10, 1, 20, "package limit"),
    maxPagesPerPackage: integer(raw.maxPagesPerPackage ?? 2, 1, 3, "page limit"),
    maxRecordsPerPackage: integer(raw.maxRecordsPerPackage ?? 50, 1, 100,
      "record limit"),
    maxAgeMinutes: integer(raw.maxAgeMinutes ?? 60, 1, 1440, "freshness threshold"),
    dryRun: raw.dryRun !== false,
  };
}
function packageKey(ecosystem: string, name: string, version: string,
  purl: string | null) {
  return [ecosystem, name, version, purl ?? ""].join("\u0000");
}
export function planOfficialOsvInspection(
  importId: string, rows: SnapshotRow[],
  bindings: PackageBinding[], maxPackages: number,
): OfficialOsvPlan {
  const byProduct = new Map(bindings.map(binding =>
    [binding.inventoryProduct.toLowerCase().normalize("NFKC").trim()
      .replace(/\s+/g, " "), binding]));
  const work = new Map<string, OfficialOsvPackageWork>();
  let mappedRows = 0;
  let unmappedRows = 0;
  let invalidVersionRows = 0;
  for (const row of rows) {
    const binding = byProduct.get(row.normalizedProductKey);
    if (!binding) {
      unmappedRows++;
      continue;
    }
    mappedRows++;
    if (row.versionStatus !== "EXACT" || !row.softwareVersion) {
      invalidVersionRows++;
      continue;
    }
    const request = validateLiveOsvRequest({
      ecosystem: binding.ecosystem,
      name: binding.packageName,
      version: row.softwareVersion,
      expectedPurl: binding.expectedPurl,
    });
    const key = packageKey(request.ecosystem, request.name,
      request.version, request.expectedPurl ?? null);
    const existing = work.get(key);
    if (existing) {
      existing.observationCount++;
      if (existing.identifiers.length < 5)
        existing.identifiers.push(row.externalId);
    } else {
      work.set(key, {
        key, ecosystem: request.ecosystem, name: request.name,
        version: request.version,
        expectedPurl: request.expectedPurl ?? null,
        observationCount: 1, identifiers: [row.externalId],
      });
    }
  }
  const sorted = [...work.values()].sort((a, b) =>
    b.observationCount - a.observationCount ||
    a.key.localeCompare(b.key));
  const selected = sorted.slice(0, maxPackages);
  return {
    importId, inventoryRows: rows.length, mappedRows, unmappedRows,
    invalidVersionRows, mappedPackages: bindings.length,
    actionablePackages: sorted.length,
    selectedPackages: selected.length,
    skippedPackages: sorted.length - selected.length,
    allRowsAccountedFor: mappedRows + unmappedRows === rows.length,
    work: selected,
    warnings: [
      "Package names and versions originate from a customer-declared CSV.",
      "Only explicitly reviewed package bindings are eligible for provider queries.",
      "Identical ecosystem/name/version queries are deduplicated across assets.",
      "Package query limits can exclude observations; omitted packages remain unknown.",
      "Preview makes no third-party requests and writes no inventory state.",
    ],
  };
}
function interpretOfficialOsvResult(
  work: OfficialOsvPackageWork,
  result: LiveOsvQueryResult, maxAgeMinutes: number, now: Date,
): OfficialOsvPackageResult {
  const queryTime = new Date(result.checkedAt);
  const ageMinutes = (now.getTime() - queryTime.getTime()) / 60000;
  const stale = !Number.isFinite(ageMinutes) || ageMinutes < -5 ||
    ageMinutes > maxAgeMinutes;
  const status = result.status !== "COMPLETE" ? result.status :
    stale ? "STALE_RESPONSE" : "COMPLETE";
  const records = result.vulnerabilities;
  return {
    key: work.key, ecosystem: work.ecosystem,
    name: work.name, version: work.version,
    observationCount: work.observationCount,
    status, checkedAt: result.checkedAt,
    digest: result.digest,
    possibleIds: records.filter(v =>
      v.packageIdentityListed && v.exactVersionListed &&
      v.withdrawn === null).map(x => x.id),
    providerOnlyIds: records.filter(v =>
      (!v.packageIdentityListed || !v.exactVersionListed) &&
      v.withdrawn === null).map(x => x.id),
    withdrawnIds: records.filter(v => v.withdrawn !== null).map(x => x.id),
    unresolvedIds: records.filter(v =>
      v.rangesPresent && !v.exactVersionListed &&
      v.withdrawn === null).map(x => x.id),
    queriedPages: result.queriedPages,
    warnings: [
      ...result.warnings,
      ...(stale ? ["OSV provider response exceeded the requested freshness threshold."] : []),
      ...(result.status !== "COMPLETE" ?
        ["OSV response is not complete; no security assurance may be derived."] : []),
    ],
  };
}
export function buildOfficialOsvInspectionReport(
  scope: AssetScope, command: OfficialOsvInspectionInput,
  plan: OfficialOsvPlan, results: OfficialOsvPackageResult[],
  now: Date,
): OfficialOsvInspectionReport {
  const complete = !command.dryRun &&
    plan.skippedPackages === 0 && plan.invalidVersionRows === 0 &&
    plan.unmappedRows === 0 && results.length === plan.actionablePackages &&
    results.every(x => x.status === "COMPLETE");
  const noResults = !command.dryRun && results.length === 0;
  const providerFailure = results.some(x => x.status === "UPSTREAM_ERROR");
  const status: OfficialOsvInspectionReport["status"] =
    command.dryRun ? "PREVIEW" :
    noResults ? "INCOMPLETE" :
    providerFailure ? "ERROR" :
    complete ? "COMPLETE" : "PARTIAL";
  const warnings = [
    ...plan.warnings,
    "OSV results are retrieved over HTTPS from a fixed upstream endpoint, not signed advisories.",
    "The OSV API can fuzzy-match versions; only affected.versions literal matches appear as possible associations.",
    "An incomplete or empty response is not proof of absence of vulnerabilities.",
    "This operation does not change CyberScore, evidence, inventory observations or remediation findings.",
    ...(complete ? [] : ["Coverage is incomplete or requires human review."]),
  ];
  const canonical = {
    schema: "cyberpilot.assets.osv.official.inspection.v1" as const,
    organizationId: scope.organizationId,
    importId: command.importId,
    inventoryOrigin: "CUSTOMER_DECLARED_CSV" as const,
    providerOrigin: "OSV_DEV_HTTPS_API" as const,
    generatedAt: now.toISOString(), dryRun: command.dryRun,
    status, coverage: "DECLARED_NOT_VERIFIED" as const,
    plan, results,
    queriesAttempted: results.length,
    queriesCompleted: results.filter(x => x.status === "COMPLETE").length,
    totalPossibleAssociations: results.reduce(
      (sum, x) => sum + x.possibleIds.length, 0),
    totalProviderOnlyAssociations: results.reduce(
      (sum, x) => sum + x.providerOnlyIds.length, 0),
    totalUnresolved: results.reduce(
      (sum, x) => sum + x.unresolvedIds.length, 0),
    totalWithdrawn: results.reduce(
      (sum, x) => sum + x.withdrawnIds.length, 0),
    warnings,
  };
  return { ...canonical, reportDigest: sha(canonical) };
}
export type OfficialOsvFetchDependencies = {
  query?: typeof queryOfficialOsv;
  now?: () => Date;
  clientOptions?: LiveOsvClientOptions;
};
export async function inspectOfficialOsv(
  scope: AssetScope, input: unknown,
  dependencies: OfficialOsvFetchDependencies = {},
): Promise<OfficialOsvInspectionReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Official provider queries require organization administrator permission.");
  const command = parseOfficialOsvInspection(input);
  const now = dependencies.now?.() ?? new Date();
  if (!Number.isFinite(now.getTime()))
    throw new WorkInputError("INVALID", "Invalid evaluation timestamp.");
  const snapshot = await db.assetInventoryImport.findFirst({
    where: { organizationId: scope.organizationId, id: command.importId },
    select: { id: true, importedCount: true, state: true },
  });
  if (!snapshot)
    throw new WorkInputError("MISSING", "Inventory snapshot not found.");
  if (snapshot.state !== "COMMITTED")
    throw new WorkInputError("CONFLICT",
      "Official queries require an active inventory snapshot.");
  if (snapshot.importedCount < 1 || snapshot.importedCount > 10000)
    throw new WorkInputError("CONFLICT", "Invalid or excessive inventory count.");
  const devices = await db.assetInventoryDevice.findMany({
    where: { organizationId: scope.organizationId, importId: snapshot.id },
    take: 10001,
    select: {
      externalId: true, softwareName: true, softwareVersion: true,
      versionStatus: true, normalizedProductKey: true,
    },
  });
  if (devices.length !== snapshot.importedCount)
    throw new WorkInputError("CONFLICT", "Incomplete snapshot coverage.");
  const plan = planOfficialOsvInspection(command.importId, devices,
    command.packageBindings, command.limitPackages);
  if (!plan.allRowsAccountedFor)
    throw new WorkInputError("CONFLICT", "Inventory mapping coverage inconsistent.");
  if (command.dryRun)
    return buildOfficialOsvInspectionReport(scope, command, plan, [], now);
  const results: OfficialOsvPackageResult[] = [];
  for (const work of plan.work) {
    const provider = await (dependencies.query ?? queryOfficialOsv)({
      ecosystem: work.ecosystem, name: work.name, version: work.version,
      expectedPurl: work.expectedPurl,
    }, {
      ...dependencies.clientOptions,
      maxPages: command.maxPagesPerPackage,
      maxRecords: command.maxRecordsPerPackage,
    });
    results.push(interpretOfficialOsvResult(work, provider,
      command.maxAgeMinutes, dependencies.now?.() ?? new Date()));
  }
  return buildOfficialOsvInspectionReport(
    scope, command, plan, results, dependencies.now?.() ?? new Date());
}
