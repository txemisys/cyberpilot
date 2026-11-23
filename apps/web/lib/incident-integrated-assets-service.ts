import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { type IncidentSnapshot, validateIncidentSnapshot,
  incidentDigest } from "./incident-case-domain";
import { assessIncidentAssetImpact, type AssetImpactSelection,
  type DeviceInventoryRecord, type AssetImportRecord,
  type AdvisoryObservation } from "./incident-integrated-assets-domain";

export class IncidentAssetIntegrationError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new IncidentAssetIntegrationError(code); }
const ident = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
function cleanIds(x: unknown, max: number): string[] {
  if (!Array.isArray(x) || x.length > max || x.some(id => !ident(id)))
    fail("ASSET_INTEGRATION_SELECTION_INVALID");
  return x as string[];
}
async function authorize(actor: IncidentActor) {
  if (!ident(actor.organizationId) || !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("ASSET_INTEGRATION_ROLE_DENIED");
  const member = await db.membership.findFirst({
    where: { userId: actor.userId, organizationId: actor.organizationId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    fail("ASSET_INTEGRATION_MEMBERSHIP_REVOKED");
}
async function caseSnapshot(organizationId: string, incidentId: string) {
  if (!ident(incidentId)) fail("ASSET_INTEGRATION_INCIDENT_ID_INVALID");
  const row = await db.guidedIncidentCase.findFirst({
    where: { id: incidentId, organizationId },
    select: { id: true, organizationId: true, revision: true, status: true,
      snapshotDigest: true, snapshot: true },
  });
  if (!row) fail("ASSET_INTEGRATION_CASE_NOT_IN_TENANT");
  const snapshot = row.snapshot as unknown as IncidentSnapshot;
  if (!snapshot || validateIncidentSnapshot(snapshot).length ||
      snapshot.id !== row.id || snapshot.organizationId !== row.organizationId ||
      snapshot.revision !== row.revision || snapshot.status !== row.status ||
      incidentDigest(snapshot) !== row.snapshotDigest)
    fail("ASSET_INTEGRATION_CASE_INTEGRITY_INVALID");
  return snapshot;
}
export type AssetIntegrationRequest = {
  incidentId: string; deviceIds: string[];
  importIds: string[]; externalIds: string[];
  freshnessHours?: number; requireActiveImport?: boolean;
};
export async function readIncidentAssetImpact(
  actor: IncidentActor, request: AssetIntegrationRequest,
) {
  await authorize(actor);
  const deviceIds = cleanIds(request.deviceIds, 150);
  const importIds = cleanIds(request.importIds, 50);
  const externalIds = cleanIds(request.externalIds, 150);
  const freshnessHours = request.freshnessHours ?? 72;
  if (!Number.isSafeInteger(freshnessHours) || freshnessHours < 1 ||
      freshnessHours > 8760 || request.requireActiveImport !== undefined &&
      typeof request.requireActiveImport !== "boolean")
    fail("ASSET_INTEGRATION_OPTIONS_INVALID");
  const snapshot = await caseSnapshot(actor.organizationId, request.incidentId);
  const selection: AssetImpactSelection = {
    deviceIds, imports: importIds, externalIds,
    requireActiveImport: request.requireActiveImport ?? true,
  };
  const org = actor.organizationId;
  // Bounded exact identifiers only. No hostname, email or owner-hash
  // correlation is allowed because identity attribution needs stronger proof.
  const deviceRows = await db.assetInventoryDevice.findMany({
    where: { organizationId: org,
      OR: [
        { id: { in: deviceIds } }, { importId: { in: importIds } },
        { externalId: { in: externalIds } },
      ],
    }, take: 601, orderBy: [{ observedAt: "desc" }, { id: "asc" }],
    select: {
      id: true, organizationId: true, importId: true, externalId: true,
      hostname: true, ownerHash: true, platform: true, osName: true,
      osVersion: true, softwareName: true, softwareVersion: true,
      normalizedProductKey: true, observedAt: true, versionStatus: true,
      freshnessStatus: true, advisoryStatus: true, advisoryIds: true,
      confidence: true,
    },
  });
  const selectedImports = [...new Set([
    ...importIds, ...deviceRows.map(x => x.importId),
  ])].slice(0, 100);
  const [imports, inspections] = await Promise.all([
    db.assetInventoryImport.findMany({ where: {
      organizationId: org, id: { in: selectedImports },
    }, take: 101, select: {
      id: true, organizationId: true, sourceLabel: true, payloadDigest: true,
      state: true, declaredCount: true, importedCount: true,
      unknownVersionCount: true, createdAt: true, retiredAt: true,
    } }),
    db.assetOsvInspection.findMany({ where: {
      organizationId: org, inventoryImportId: { in: selectedImports },
    }, take: 151, orderBy: [{ completedAt: "desc" }, { id: "asc" }],
      select: {
        id: true, organizationId: true, inventoryImportId: true,
        status: true, coverage: true, provider: true,
        queryCount: true, completedCount: true, possibleCount: true,
        providerOnlyCount: true, completedAt: true, reportDigest: true,
      },
    }),
  ]);
  const devices: DeviceInventoryRecord[] = deviceRows.slice(0, 600).map(x => ({
    ...x, observedAt: x.observedAt.toISOString(),
    advisoryIds: Array.isArray(x.advisoryIds) ?
      x.advisoryIds.filter((id): id is string => typeof id === "string") : [],
  }));
  const assetImports: AssetImportRecord[] = imports.slice(0, 100).map(x => ({
    ...x, state: String(x.state), createdAt: x.createdAt.toISOString(),
    retiredAt: x.retiredAt?.toISOString() ?? null,
  }));
  const advisory: AdvisoryObservation[] = inspections.slice(0, 150).map(x => ({
    ...x, completedAt: x.completedAt.toISOString(),
  }));
  const result = assessIncidentAssetImpact({
    incident: snapshot, selection, devices, imports: assetImports,
    inspections: advisory, at: new Date().toISOString(), freshnessHours,
    truncated: deviceRows.length > 600 || imports.length > 100 ||
      inspections.length > 150 || selectedImports.length === 100,
  });
  return {
    schema: "cyberpilot.incident.asset-impact.read.v1" as const,
    organizationId: org, incidentId: snapshot.id,
    impact: result,
    externalProviderQueries: 0 as const,
    deviceIsolationOperations: 0 as const,
    liveDeviceDispositionVerified: false as const,
    cyberScoreModified: false as const,
  };
}
export async function discoverIncidentAssetReferences(
  actor: IncidentActor, input: {
    importId?: string; offset?: number; limit?: number;
  } = {},
) {
  await authorize(actor);
  const offset = input.offset ?? 0, limit = input.limit ?? 30;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      input.importId !== undefined && !ident(input.importId))
    fail("ASSET_INTEGRATION_LIST_INVALID");
  const where = { organizationId: actor.organizationId,
    ...(input.importId ? { importId: input.importId } : {}) };
  const [devices, total, imports] = await Promise.all([
    db.assetInventoryDevice.findMany({ where, take: limit, skip: offset,
      orderBy: [{ observedAt: "desc" }, { id: "asc" }],
      select: { id: true, importId: true, externalId: true,
        platform: true, osName: true, osVersion: true,
        softwareName: true, softwareVersion: true, observedAt: true,
        advisoryStatus: true, confidence: true } }),
    db.assetInventoryDevice.count({ where }),
    db.assetInventoryImport.findMany({ where: {
      organizationId: actor.organizationId },
      orderBy: { createdAt: "desc" }, take: 50,
      select: { id: true, sourceLabel: true, state: true,
        importedCount: true, createdAt: true, retiredAt: true } }),
  ]);
  return {
    schema: "cyberpilot.incident.asset-inventory.references.v1" as const,
    organizationId: actor.organizationId, offset, limit, total,
    nextOffset: offset + limit < total ? offset + limit : null,
    devices: devices.map(x => ({
      ...x, observedAt: x.observedAt.toISOString(),
    })), imports: imports.map(x => ({
      ...x, state: String(x.state), createdAt: x.createdAt.toISOString(),
      retiredAt: x.retiredAt?.toISOString() ?? null,
    })),
    importedDataOnly: true as const, realTimeDeviceRead: false as const,
  };
}
export async function reviewIncidentAssetExposure(
  actor: IncidentActor, incidentId: string, deviceIds: string[],
) {
  const impact = await readIncidentAssetImpact(actor, {
    incidentId, deviceIds, externalIds: [], importIds: [],
    requireActiveImport: true, freshnessHours: 72,
  });
  const impacted = impact.impact.affectedDevices;
  const advisory = impacted.filter(x => x.advisoryStatus !== "NONE");
  return {
    schema: "cyberpilot.incident.asset-exposure.review.v1" as const,
    organizationId: actor.organizationId, incidentId,
    affectedDevices: impacted.length, advisoryCandidates: advisory.length,
    unconfirmedDeviceCount: impacted.filter(x =>
      x.outcome !== "OBSERVED_ASSET").length,
    advisoryByProduct: impact.impact.groups.map(x => ({
      productKey: x.productKey, affected: x.count,
      advisoryCandidates: x.advisoryPossible,
      unknown: x.unknownCount,
    })), warnings: impact.impact.findings,
    sourceDigest: impact.impact.sourceDigest,
    advisoryNotIncidentAttribution: true as const,
    providerScanPerformed: false as const,
    actualAssetIsolationPerformed: false as const,
  };
}
