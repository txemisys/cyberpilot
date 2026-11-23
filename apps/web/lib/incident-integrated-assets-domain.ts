import { createHash } from "node:crypto";
import { type IncidentSnapshot, validateIncidentSnapshot,
  incidentDigest } from "./incident-case-domain";
import { getIncidentPlaybook } from "./incident-playbook-catalog";

export type DeviceInventoryRecord = {
  id: string; organizationId: string; importId: string;
  externalId: string; hostname: string | null; ownerHash: string | null;
  platform: string; osName: string; osVersion: string | null;
  softwareName: string; softwareVersion: string | null;
  normalizedProductKey: string; observedAt: string;
  versionStatus: string; freshnessStatus: string;
  advisoryStatus: string; advisoryIds: string[];
  confidence: string;
};
export type AssetImportRecord = {
  id: string; organizationId: string; sourceLabel: string;
  payloadDigest: string; state: string; declaredCount: number;
  importedCount: number; unknownVersionCount: number;
  createdAt: string; retiredAt: string | null;
};
export type AdvisoryObservation = {
  id: string; organizationId: string; inventoryImportId: string;
  status: string; coverage: string; provider: string;
  queryCount: number; completedCount: number;
  possibleCount: number; providerOnlyCount: number;
  completedAt: string; reportDigest: string;
};
export type ImpactLink = { externalId: string; importId: string;
  justification: "EXPLICIT_INVENTORY_ID" | "EXPLICIT_DEVICE_EXTERNAL_ID";
};
export type AssetImpactSelection = {
  deviceIds: string[]; imports: string[];
  externalIds: string[]; requireActiveImport: boolean;
};
export type AssetImpactOutcome = "OBSERVED_ASSET" | "STALE_ASSET" |
  "DECLARED_ASSET" | "UNKNOWN_VERSION" | "RETIRED_IMPORT" |
  "CONFLICTED_IMPORT" | "NO_DATA" | "FOREIGN_TENANT_REJECTED";
export type AffectedDevice = {
  id: string; organizationId: string; incidentId: string;
  inventoryImportId: string; externalId: string;
  productKey: string; platform: string; osName: string;
  osVersion: string | null; softwareName: string;
  softwareVersion: string | null; observedAt: string;
  matchBasis: "EXPLICIT_DEVICE_ID" | "EXPLICIT_EXTERNAL_ID" |
    "EXPLICIT_IMPORT_SCOPE";
  outcome: AssetImpactOutcome; freshnessHours: number;
  advisoryStatus: string; advisoryIds: string[];
  confidence: string; importState: string; sourceLabel: string;
  warnings: string[]; needsHumanAttribution: boolean;
  deviceIsolated: false; providerWriteProven: false;
};
export type AssetImpactGroup = {
  productKey: string; count: number; staleCount: number;
  unknownCount: number; advisoryPossible: number;
  deviceIds: string[]; needsIndependentOwnerConfirmation: true;
};
export type AssetImpactAssessment = {
  schema: "cyberpilot.incident.asset-impact.v1";
  organizationId: string; incidentId: string;
  incidentType: string; at: string;
  sourceDigest: string; incidentDigest: string;
  deviceRowsObserved: number; importRowsObserved: number;
  advisoryRowsObserved: number; truncated: boolean;
  selectedDeviceIds: number; selectedImportIds: number;
  selectedExternalIds: number;
  affectedDevices: AffectedDevice[]; groups: AssetImpactGroup[];
  advisoryObservations: AdvisoryObservation[];
  missingDeviceIds: string[]; missingImportIds: string[];
  missingExternalIds: string[]; foreignTenantIds: string[];
  conflictingExternalIds: string[]; staleDeviceIds: string[];
  unknownVersionIds: string[]; highPriorityDeviceIds: string[];
  coverage: "NO_EXPLICIT_SCOPE" | "PARTIAL" | "EXPLICIT_SCOPE_MATCHED";
  reviewGate: "BLOCKED" | "INCOMPLETE" | "READY_FOR_OPERATOR_REVIEW";
  findings: string[]; riskReductionProven: false;
  remoteDeviceIsolationVerified: false;
  vulnerabilityScanPerformed: false; providerCalls: 0;
};
export type AssetImpactInput = {
  incident: IncidentSnapshot; selection: AssetImpactSelection;
  devices: DeviceInventoryRecord[]; imports: AssetImportRecord[];
  inspections: AdvisoryObservation[]; at: string;
  freshnessHours: number; truncated: boolean;
};
const ident = (value: unknown): value is string => typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
const validTime = (value: unknown): value is string =>
  typeof value === "string" && Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const checksum = (value: unknown) => createHash("sha256")
  .update(JSON.stringify(value)).digest("hex");
function ids(values: unknown, limit: number) {
  if (!Array.isArray(values) || values.length > limit ||
      values.some(x => !ident(x))) throw Error("ASSET_IMPACT_IDS_INVALID");
  return values as string[];
}
function check(input: AssetImpactInput) {
  if (validateIncidentSnapshot(input.incident).length ||
      !validTime(input.at) || !Number.isSafeInteger(input.freshnessHours) ||
      input.freshnessHours < 1 || input.freshnessHours > 8760 ||
      input.devices.length > 600 || input.imports.length > 100 ||
      input.inspections.length > 150)
    throw Error("ASSET_IMPACT_SOURCE_INVALID");
  ids(input.selection.deviceIds, 150);
  ids(input.selection.imports, 50);
  ids(input.selection.externalIds, 150);
  if (typeof input.selection.requireActiveImport !== "boolean" ||
      typeof input.truncated !== "boolean")
    throw Error("ASSET_IMPACT_OPTIONS_INVALID");
}
function effectiveMatch(row: DeviceInventoryRecord, input: AssetImpactSelection):
  AffectedDevice["matchBasis"] | null {
  if (input.deviceIds.includes(row.id)) return "EXPLICIT_DEVICE_ID";
  if (input.externalIds.includes(row.externalId)) return "EXPLICIT_EXTERNAL_ID";
  if (input.imports.includes(row.importId)) return "EXPLICIT_IMPORT_SCOPE";
  return null;
}
function normalizeAdvisoryIds(values: string[]) {
  return [...new Set(values.filter(x => typeof x === "string" &&
    x.length <= 100 && /^[a-zA-Z0-9_.:-]+$/.test(x)))].sort();
}
export function assessIncidentAssetImpact(input: AssetImpactInput): AssetImpactAssessment {
  check(input);
  const { incident, selection, devices, imports, inspections } = input;
  const org = incident.organizationId;
  const foreignTenantIds = [...devices, ...imports, ...inspections]
    .filter(x => x.organizationId !== org).map(x => x.id);
  const localImports = imports.filter(x => x.organizationId === org);
  const importMap = new Map(localImports.map(x => [x.id, x]));
  const candidate = devices.filter(x => x.organizationId === org &&
    effectiveMatch(x, selection) !== null);
  const affectedDevices: AffectedDevice[] = candidate.map(row => {
    const entry = importMap.get(row.importId);
    const age = Math.max(0,
      (Date.parse(input.at) - Date.parse(row.observedAt)) / 3600000);
    const stale = !Number.isFinite(age) ||
      Date.parse(row.observedAt) > Date.parse(input.at) ||
      age > input.freshnessHours;
    const retired = !!entry && (entry.state !== "COMMITTED" ||
      entry.retiredAt !== null);
    const versionUnknown = !row.osVersion || !row.softwareVersion &&
      Boolean(row.softwareName) || row.versionStatus !== "KNOWN";
    const warnings = [
      ...(!entry ? ["IMPORT_MISSING"] : []),
      ...(retired ? ["IMPORT_RETIRED_OR_UNCOMMITTED"] : []),
      ...(stale ? ["ASSET_OBSERVATION_STALE"] : []),
      ...(versionUnknown ? ["VERSION_UNKNOWN"] : []),
      ...(!["OBSERVED", "VERIFIED"].includes(row.confidence) ?
        ["INVENTORY_CONFIDENCE_NOT_INDEPENDENTLY_VERIFIED"] : []),
      ...(row.advisoryStatus !== "NONE" ? ["ADVISORY_DISPOSITION_REQUIRED"] : []),
    ];
    const outcome: AssetImpactOutcome = !entry ? "NO_DATA" :
      retired ? "RETIRED_IMPORT" : stale ? "STALE_ASSET" :
      versionUnknown ? "UNKNOWN_VERSION" :
      row.confidence !== "OBSERVED" ? "DECLARED_ASSET" : "OBSERVED_ASSET";
    return {
      id: row.id, organizationId: org, incidentId: incident.id,
      inventoryImportId: row.importId, externalId: row.externalId,
      productKey: row.normalizedProductKey,
      platform: row.platform, osName: row.osName, osVersion: row.osVersion,
      softwareName: row.softwareName, softwareVersion: row.softwareVersion,
      observedAt: row.observedAt, matchBasis: effectiveMatch(row, selection)!,
      outcome, freshnessHours: age,
      advisoryStatus: row.advisoryStatus,
      advisoryIds: normalizeAdvisoryIds(row.advisoryIds),
      confidence: row.confidence, importState: entry?.state ?? "MISSING",
      sourceLabel: entry?.sourceLabel ?? "UNKNOWN",
      warnings, needsHumanAttribution: true,
      deviceIsolated: false, providerWriteProven: false,
    };
  });
  const selectedIds = new Set(affectedDevices.map(x => x.id));
  const selectedImports = new Set(affectedDevices.map(x => x.inventoryImportId));
  const selectedExternals = new Set(affectedDevices.map(x => x.externalId));
  const missingDeviceIds = selection.deviceIds.filter(x => !selectedIds.has(x));
  const missingImportIds = selection.imports.filter(x =>
    !localImports.some(i => i.id === x));
  const missingExternalIds = selection.externalIds.filter(x =>
    !selectedExternals.has(x));
  const byExternal = new Map<string, Set<string>>();
  for (const item of affectedDevices) {
    const current = byExternal.get(item.externalId) ?? new Set();
    current.add(item.inventoryImportId);
    byExternal.set(item.externalId, current);
  }
  const conflictingExternalIds = [...byExternal].filter(([, values]) =>
    values.size > 1).map(([id]) => id).sort();
  for (const item of affectedDevices) {
    if (conflictingExternalIds.includes(item.externalId)) {
      item.outcome = "CONFLICTED_IMPORT";
      item.warnings.push("SAME_EXTERNAL_ID_ACROSS_INVENTORY_IMPORTS");
    }
  }
  const groups = new Map<string, AffectedDevice[]>();
  for (const item of affectedDevices) {
    const key = item.productKey || "UNKNOWN_PRODUCT";
    const rows = groups.get(key) ?? [];
    rows.push(item);
    groups.set(key, rows);
  }
  const grouped: AssetImpactGroup[] = [...groups].map(([productKey, rows]) => ({
    productKey, count: rows.length,
    staleCount: rows.filter(x => x.outcome === "STALE_ASSET").length,
    unknownCount: rows.filter(x => x.outcome === "UNKNOWN_VERSION" ||
      x.outcome === "NO_DATA").length,
    advisoryPossible: rows.filter(x => x.advisoryStatus !== "NONE").length,
    deviceIds: rows.map(x => x.id).sort(),
    needsIndependentOwnerConfirmation: true,
  })).sort((a, b) => b.advisoryPossible - a.advisoryPossible ||
    b.count - a.count || a.productKey.localeCompare(b.productKey));
  const associatedInspections = inspections.filter(x => x.organizationId === org &&
    selectedImports.has(x.inventoryImportId));
  const issues = [
    ...(input.truncated ? ["SOURCE_ROWS_TRUNCATED"] : []),
    ...(foreignTenantIds.length ? ["CROSS_TENANT_ROWS_EXCLUDED"] : []),
    ...(missingDeviceIds.length ? ["EXPLICIT_DEVICE_NOT_FOUND"] : []),
    ...(missingImportIds.length ? ["EXPLICIT_IMPORT_NOT_FOUND"] : []),
    ...(missingExternalIds.length ? ["EXPLICIT_EXTERNAL_ID_NOT_FOUND"] : []),
    ...(conflictingExternalIds.length ? ["MULTIPLE_IMPORTS_FOR_EXTERNAL_ID"] : []),
    ...(affectedDevices.some(x => x.outcome !== "OBSERVED_ASSET") ?
      ["DEVICE_EVIDENCE_NOT_CURRENTLY_OBSERVED"] : []),
    ...(associatedInspections.some(x => x.status !== "COMPLETED") ?
      ["ADVISORY_INSPECTION_INCOMPLETE"] : []),
    ...(incident.type === "LOST_DEVICE" && !affectedDevices.length ?
      ["LOST_DEVICE_IDENTITY_NOT_PROVEN"] : []),
    ...(incident.type === "RANSOMWARE" && affectedDevices.some(x =>
      x.advisoryStatus !== "NONE") ?
      ["ADVISORY_EXPOSURE_NOT_RANSOMWARE_CAUSALITY"] : []),
  ];
  const explicit = selection.deviceIds.length +
    selection.externalIds.length + selection.imports.length;
  return {
    schema: "cyberpilot.incident.asset-impact.v1",
    organizationId: org, incidentId: incident.id, incidentType: incident.type,
    at: input.at, sourceDigest: checksum({
      devices: devices.map(x => [x.id, x.observedAt, x.advisoryStatus]),
      imports: imports.map(x => [x.id, x.state, x.retiredAt]),
      inspections: inspections.map(x => [x.id, x.reportDigest]),
    }), incidentDigest: incidentDigest(incident),
    deviceRowsObserved: devices.length, importRowsObserved: imports.length,
    advisoryRowsObserved: inspections.length, truncated: input.truncated,
    selectedDeviceIds: selection.deviceIds.length,
    selectedImportIds: selection.imports.length,
    selectedExternalIds: selection.externalIds.length,
    affectedDevices, groups: grouped,
    advisoryObservations: associatedInspections,
    missingDeviceIds, missingImportIds, missingExternalIds,
    foreignTenantIds, conflictingExternalIds,
    staleDeviceIds: affectedDevices.filter(x =>
      x.outcome === "STALE_ASSET").map(x => x.id),
    unknownVersionIds: affectedDevices.filter(x =>
      x.outcome === "UNKNOWN_VERSION").map(x => x.id),
    highPriorityDeviceIds: affectedDevices.filter(x =>
      x.advisoryStatus !== "NONE" ||
      ["UNKNOWN_VERSION", "CONFLICTED_IMPORT", "STALE_ASSET"].includes(x.outcome))
      .map(x => x.id),
    coverage: explicit === 0 ? "NO_EXPLICIT_SCOPE" :
      missingDeviceIds.length || missingImportIds.length ||
      missingExternalIds.length ? "PARTIAL" : "EXPLICIT_SCOPE_MATCHED",
    reviewGate: foreignTenantIds.length || conflictingExternalIds.length ?
      "BLOCKED" : issues.length ? "INCOMPLETE" : "READY_FOR_OPERATOR_REVIEW",
    findings: issues, riskReductionProven: false,
    remoteDeviceIsolationVerified: false,
    vulnerabilityScanPerformed: false, providerCalls: 0,
  };
}
export function compareAssetImpactAssessments(
  before: AssetImpactAssessment, after: AssetImpactAssessment,
) {
  if (before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId || before.at > after.at)
    throw Error("ASSET_IMPACT_COMPARISON_SCOPE_INVALID");
  const oldDevices = new Map(before.affectedDevices.map(x => [x.id, x]));
  const newDevices = new Map(after.affectedDevices.map(x => [x.id, x]));
  return {
    schema: "cyberpilot.incident.asset-impact.diff.v1" as const,
    organizationId: before.organizationId, incidentId: before.incidentId,
    appeared: [...newDevices.keys()].filter(x => !oldDevices.has(x)),
    disappeared: [...oldDevices.keys()].filter(x => !newDevices.has(x)),
    statusChanges: [...newDevices.values()].filter(x =>
      oldDevices.has(x.id) && oldDevices.get(x.id)!.outcome !== x.outcome)
      .map(x => ({ id: x.id, from: oldDevices.get(x.id)!.outcome,
        to: x.outcome })),
    beforeTruncated: before.truncated, afterTruncated: after.truncated,
    originalScopeComparable: before.selectedDeviceIds === after.selectedDeviceIds &&
      before.selectedImportIds === after.selectedImportIds &&
      before.selectedExternalIds === after.selectedExternalIds,
    causeOfIncidentProven: false as const,
    containmentConfirmed: false as const,
  };
}
