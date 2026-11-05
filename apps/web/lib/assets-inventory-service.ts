import { db } from "@cyberpilot/database";
import { canManageWork, canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { analyzeCsvInventory, inventoryHash } from "./assets-csv-inventory";
import type { InventoryAdvisory, InventoryImportReport } from "./assets-csv-inventory";

export type AssetScope = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type AssetImportInput = {
  sourceLabel: string;
  idempotencyKey: string;
  csv: string;
  dryRun: boolean;
  advisories: InventoryAdvisory[];
};
export type AssetInventoryQuery = {
  importId?: string;
  assetId?: string;
  platform?: string;
  versionStatus?: string;
  advisoryStatus?: string;
  offset: number;
  limit: number;
  includeRetired: boolean;
};
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected asset inventory object.");
  return value as Record<string, unknown>;
}
function keys(value: Record<string, unknown>, allowed: readonly string[]) {
  if (Object.keys(value).some(key => !allowed.includes(key)))
    throw new WorkInputError("INVALID", "Unknown asset inventory field.");
}
function number(value: unknown, name: string, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < 0 || value > max)
    throw new WorkInputError("INVALID", "Invalid inventory " + name + ".");
  return value;
}
function short(value: unknown, label: string, maximum: number) {
  if (typeof value !== "string" || !value.trim() ||
      value.length > maximum || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value.trim();
}
export function parseAssetImport(value: unknown): AssetImportInput {
  const raw = object(value);
  keys(raw, ["sourceLabel", "idempotencyKey", "csv", "dryRun", "advisories"]);
  if (raw.dryRun !== undefined && typeof raw.dryRun !== "boolean")
    throw new WorkInputError("INVALID", "Invalid dryRun flag.");
  if (typeof raw.csv !== "string" ||
      Buffer.byteLength(raw.csv, "utf8") > 262144)
    throw new WorkInputError("INVALID", "CSV exceeds the 256 KiB limit.");
  if (raw.advisories !== undefined && !Array.isArray(raw.advisories))
    throw new WorkInputError("INVALID", "Advisories must be an array.");
  return {
    sourceLabel: short(raw.sourceLabel, "source label", 120),
    idempotencyKey: short(raw.idempotencyKey, "idempotency key", 150),
    csv: raw.csv,
    dryRun: raw.dryRun !== false,
    advisories: (raw.advisories ?? []) as InventoryAdvisory[],
  };
}
export function parseAssetQuery(value: unknown): AssetInventoryQuery {
  const raw = object(value);
  keys(raw, [
    "importId", "assetId", "platform", "versionStatus",
    "advisoryStatus", "offset", "limit", "includeRetired",
  ]);
  if (raw.includeRetired !== undefined && typeof raw.includeRetired !== "boolean")
    throw new WorkInputError("INVALID", "Invalid includeRetired.");
  const platforms = ["WINDOWS","MACOS","LINUX","ANDROID","IOS","OTHER","UNKNOWN"];
  const versions = ["EXACT","MISSING","AMBIGUOUS"];
  const advisories = ["UNKNOWN","NO_MATCH","POSSIBLE_MATCH"];
  const platform = raw.platform === undefined ? undefined :
    short(raw.platform, "platform", 20).toUpperCase();
  const versionStatus = raw.versionStatus === undefined ? undefined :
    short(raw.versionStatus, "version status", 20).toUpperCase();
  const advisoryStatus = raw.advisoryStatus === undefined ? undefined :
    short(raw.advisoryStatus, "advisory status", 20).toUpperCase();
  if ((platform && !platforms.includes(platform)) ||
      (versionStatus && !versions.includes(versionStatus)) ||
      (advisoryStatus && !advisories.includes(advisoryStatus)))
    throw new WorkInputError("INVALID", "Unsupported inventory filter.");
  return {
    ...(raw.importId === undefined ? {} : {
      importId: parseWorkId(raw.importId, "import ID"),
    }),
    ...(raw.assetId === undefined ? {} : {
      assetId: short(raw.assetId, "asset ID", 100),
    }),
    ...(platform === undefined ? {} : { platform }),
    ...(versionStatus === undefined ? {} : { versionStatus }),
    ...(advisoryStatus === undefined ? {} : { advisoryStatus }),
    offset: number(raw.offset ?? 0, "offset", 1000000),
    limit: number(raw.limit ?? 50, "limit", 100),
    includeRetired: raw.includeRetired === true,
  };
}
export function assetImportFingerprint(input: AssetImportInput, report: InventoryImportReport) {
  return inventoryHash({
    sourceLabel: input.sourceLabel, csvDigest: inventoryHash(input.csv),
    advisoryDigest: inventoryHash(input.advisories),
    normalizedDigest: report.digest,
  });
}
export async function importAssetInventory(
  scope: AssetScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Inventory import requires administrator access.");
  const input = parseAssetImport(value);
  const report = analyzeCsvInventory(input.csv, {
    sourceLabel: input.sourceLabel, organizationId: scope.organizationId,
    now, advisories: input.advisories,
  });
  const fingerprint = assetImportFingerprint(input, report);
  if (input.dryRun)
    return {
      dryRun: true, replayed: false,
      importId: null, state: "PREVIEW" as const, report,
      limitations: ["Preview performs no database writes or external provider calls."],
    };
  return db.$transaction(async tx => {
    const existing = await tx.assetInventoryImport.findUnique({
      where: {
        organizationId_idempotencyKey: {
          organizationId: scope.organizationId,
          idempotencyKey: input.idempotencyKey,
        },
      },
    });
    if (existing) {
      if (existing.payloadDigest !== fingerprint ||
          existing.sourceLabel !== input.sourceLabel)
        throw new WorkInputError("CONFLICT",
          "Import idempotency key reused with a different payload.");
      return {
        dryRun: false, replayed: true,
        importId: existing.id, state: existing.state, report,
        limitations: ["Existing import reused; no new device observations created."],
      };
    }
    const imported = await tx.assetInventoryImport.create({
      data: {
        organizationId: scope.organizationId, actorUserId: scope.userId,
        idempotencyKey: input.idempotencyKey, payloadDigest: fingerprint,
        sourceLabel: input.sourceLabel, schemaVersion: 1,
        declaredCount: report.declaredCount,
        importedCount: report.importedCount,
        duplicateCount: report.duplicateCount,
        unknownVersionCount: report.unknownVersionCount,
      },
    });
    await tx.assetInventoryDevice.createMany({
      data: report.rows.map(row => ({
        organizationId: scope.organizationId, importId: imported.id,
        externalId: row.assetId, hostname: row.hostname,
        ownerHash: row.ownerHash, platform: row.platform,
        osName: row.osName, osVersion: row.osVersion,
        softwareName: row.softwareName,
        softwareVersion: row.softwareVersion,
        observedAt: row.observedAt, sourceRow: row.sourceRow,
        normalizedProductKey: row.normalizedProductKey,
        versionStatus: row.versionStatus,
        freshnessStatus: row.freshnessStatus,
        advisoryStatus: row.advisoryStatus,
        advisoryIds: row.advisoryIds,
        confidence: row.confidence,
      })),
    });
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assets.csv.import.committed",
        resourceType: "AssetInventoryImport", resourceId: imported.id,
        metadata: {
          schema: "cyberpilot.assets.csv.import.v1",
          digest: report.digest, fingerprint,
          sourceLabel: input.sourceLabel,
          declared: report.declaredCount,
          imported: report.importedCount,
          duplicates: report.duplicateCount,
          possibleMatches: report.possibleAdvisoryCount,
          declaration: "CUSTOMER_DECLARED_CSV",
        },
      },
    });
    return {
      dryRun: false, replayed: false,
      importId: imported.id, state: imported.state, report,
      limitations: [
        "Customer-declared observations are not live endpoint telemetry.",
        "This transaction does not update existing CyberScore or findings.",
      ],
    };
  });
}
export async function listAssetInventoryImports(
  scope: AssetScope, value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Inventory access denied.");
  const query = parseAssetQuery(value);
  const where = {
    organizationId: scope.organizationId,
    ...(query.includeRetired ? {} : { state: "COMMITTED" as const }),
  };
  const [total, imports] = await db.$transaction([
    db.assetInventoryImport.count({ where }),
    db.assetInventoryImport.findMany({
      where, orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, sourceLabel: true, state: true,
        declaredCount: true, importedCount: true,
        duplicateCount: true, unknownVersionCount: true,
        createdAt: true, retiredAt: true, payloadDigest: true,
      },
    }),
  ]);
  return {
    schema: "cyberpilot.assets.csv.imports.v1", total,
    offset: query.offset, limit: query.limit,
    hasMore: query.offset + imports.length < total,
    imports,
    limitations: [
      "Snapshots are user-declared and are not proof of device coverage.",
      "Retired records remain available to authorized auditors until purged.",
    ],
  };
}
export async function listAssetInventoryDevices(
  scope: AssetScope, value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Inventory access denied.");
  const query = parseAssetQuery(value);
  if (query.importId) {
    const found = await db.assetInventoryImport.findFirst({
      where: { id: query.importId, organizationId: scope.organizationId },
      select: { id: true },
    });
    if (!found) throw new WorkInputError("MISSING", "Import not found.");
  }
  const where = {
    organizationId: scope.organizationId,
    ...(query.importId ? { importId: query.importId } : {}),
    ...(query.assetId ? { externalId: query.assetId } : {}),
    ...(query.platform ? { platform: query.platform } : {}),
    ...(query.versionStatus ? { versionStatus: query.versionStatus } : {}),
    ...(query.advisoryStatus ? { advisoryStatus: query.advisoryStatus } : {}),
    ...(query.includeRetired ? {} : {
      import: { state: "COMMITTED" as const },
    }),
  };
  const [total, devices] = await db.$transaction([
    db.assetInventoryDevice.count({ where }),
    db.assetInventoryDevice.findMany({
      where, orderBy: [
        { observedAt: "desc" }, { id: "desc" },
      ], skip: query.offset, take: query.limit,
      select: {
        id: true, importId: true, externalId: true,
        hostname: true, ownerHash: true, platform: true,
        osName: true, osVersion: true,
        softwareName: true, softwareVersion: true,
        observedAt: true, sourceRow: true,
        versionStatus: true, freshnessStatus: true,
        advisoryStatus: true, advisoryIds: true, confidence: true,
      },
    }),
  ]);
  return {
    schema: "cyberpilot.assets.csv.devices.v1", total,
    offset: query.offset, limit: query.limit,
    hasMore: query.offset + devices.length < total, devices,
    limitations: [
      "Advisory matches are possible associations, not confirmed exposures.",
      "An unknown version or empty feed is unknown, never safe by default.",
      "Device freshness is classified at import time, not continuously refreshed.",
    ],
  };
}
export function parseInventoryRetirement(value: unknown) {
  const raw = object(value);
  keys(raw, ["importId", "reason", "expectedState"]);
  if (raw.expectedState !== "COMMITTED")
    throw new WorkInputError("INVALID", "Retirement requires expected COMMITTED state.");
  const reason = short(raw.reason, "retirement reason", 1000);
  if (reason.length < 12)
    throw new WorkInputError("INVALID", "Retirement reason must be explicit.");
  return {
    importId: parseWorkId(raw.importId, "import ID"),
    reason, expectedState: "COMMITTED" as const,
  };
}
export async function retireAssetInventory(
  scope: AssetScope, value: unknown, now = new Date(),
) {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Retirement requires administrator access.");
  const input = parseInventoryRetirement(value);
  return db.$transaction(async tx => {
    const found = await tx.assetInventoryImport.findFirst({
      where: { id: input.importId, organizationId: scope.organizationId },
    });
    if (!found) throw new WorkInputError("MISSING", "Import not found.");
    if (found.state !== input.expectedState)
      throw new WorkInputError("CONFLICT", "Import already retired.");
    const updated = await tx.assetInventoryImport.updateMany({
      where: {
        id: found.id, organizationId: scope.organizationId,
        state: "COMMITTED",
      },
      data: { state: "RETIRED", retiredAt: now },
    });
    if (updated.count !== 1)
      throw new WorkInputError("CONFLICT", "Import state changed concurrently.");
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assets.csv.import.retired",
        resourceType: "AssetInventoryImport", resourceId: found.id,
        metadata: { reason: input.reason,
          payloadDigest: found.payloadDigest, retiredAt: now.toISOString() },
      },
    });
    return { importId: found.id, state: "RETIRED" as const,
      retiredAt: now.toISOString() };
  });
}
