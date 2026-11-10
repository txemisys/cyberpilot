import { db } from "@cyberpilot/database";
import { WorkInputError, canReadWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  buildAssetAdviceReport, parseAssetAdviceInput,
} from "./assets-action-guidance";
import type {
  AssetAdviceInput, AssetAdviceReport, AdviceSnapshot,
} from "./assets-action-guidance";

/**
 * All data is read from a single organization. The inventory and inspection
 * must refer to the same committed snapshot. A provider's result is a
 * historical observation, not a current authenticated endpoint measurement.
 */
export async function readAssetAdviceSnapshot(
  scope: AssetScope, input: AssetAdviceInput,
): Promise<AdviceSnapshot> {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Insufficient permissions to read asset advice.");
  const [inventory, inspection] = await Promise.all([
    db.assetInventoryImport.findFirst({
      where: { id: input.importId,
        organizationId: scope.organizationId },
      select: {
        id: true, state: true, importedCount: true,
        payloadDigest: true,
      },
    }),
    db.assetOsvInspection.findFirst({
      where: {
        id: input.inspectionId,
        organizationId: scope.organizationId,
        inventoryImportId: input.importId,
      },
      select: {
        id: true, status: true, completedAt: true,
        reportDigest: true, queryCount: true,
        completedCount: true,
      },
    }),
  ]);
  if (!inventory || !inspection)
    throw new WorkInputError("MISSING",
      "The selected inventory and inspection are not associated in this tenant.");
  if (inventory.state !== "COMMITTED")
    throw new WorkInputError("CONFLICT",
      "Action advice requires an active, committed snapshot.");
  if (inventory.importedCount > 10000 ||
      inspection.queryCount > 10000)
    throw new WorkInputError("CONFLICT",
      "Persisted inventory or inspection exceeds bounded report capacity.");
  const [devices, queries] = await Promise.all([
    db.assetInventoryDevice.findMany({
      where: {
        organizationId: scope.organizationId,
        importId: input.importId,
      },
      orderBy: [{ sourceRow: "asc" }, { id: "asc" }],
      take: 10001,
      select: {
        externalId: true, softwareName: true,
        softwareVersion: true, normalizedProductKey: true,
        versionStatus: true, freshnessStatus: true,
        observedAt: true, sourceRow: true,
      },
    }),
    db.assetOsvQueryRecord.findMany({
      where: {
        organizationId: scope.organizationId,
        inspectionId: input.inspectionId,
      },
      orderBy: [{ ecosystem: "asc" }, { packageName: "asc" },
        { version: "asc" }],
      take: 10001,
      select: {
        ecosystem: true, packageName: true,
        version: true, providerStatus: true,
        possibleIds: true, providerOnlyIds: true,
        unresolvedIds: true, withdrawnIds: true,
      },
    }),
  ]);
  if (devices.length !== inventory.importedCount ||
      queries.length !== inspection.queryCount ||
      queries.length > 10000 || devices.length > 10000)
    throw new WorkInputError("CONFLICT",
      "Stored evidence count failed full-snapshot consistency checks.");
  if (inspection.completedCount > inspection.queryCount)
    throw new WorkInputError("CONFLICT",
      "Stored OSV inspection has inconsistent query counts.");
  return {
    importId: inventory.id, inspectionId: inspection.id,
    inventoryDigest: inventory.payloadDigest,
    inspectionDigest: inspection.reportDigest,
    inspectionStatus: inspection.status,
    inspectionCompletedAt: inspection.completedAt,
    importedCount: inventory.importedCount, devices, queries,
  };
}
export async function inspectAssetActionGuidance(
  scope: AssetScope, raw: unknown,
  now = new Date(),
): Promise<AssetAdviceReport> {
  const input = parseAssetAdviceInput(raw);
  const snapshot = await readAssetAdviceSnapshot(scope, input);
  return buildAssetAdviceReport(
    scope.organizationId, input, snapshot, now);
}
/**
 * A separate deterministic summary for product acceptance. It never
 * conflates actionable reviews with verified security incidents.
 */
export function validateAdvicePresentation(
  report: AssetAdviceReport,
): {
  valid: boolean;
  counted: number;
  possibleOnPage: number;
  missingEvidence: number;
  unacceptableClaims: number;
  reasons: string[];
} {
  const issues: string[] = [];
  let missingEvidence = 0;
  let unacceptableClaims = 0;
  const unique = new Set<string>();
  for (const row of report.rows) {
    if (unique.has(row.id))
      issues.push("A displayed evidence identity was repeated.");
    unique.add(row.id);
    if (row.inspectionId !== report.inspectionId ||
        row.inspectionDigest !== report.inspectionDigest ||
        row.inventoryDigest !== report.inventoryDigest ||
        !/^[a-f0-9]{64}$/.test(row.evidenceFingerprint))
      missingEvidence++;
    if (!row.notRemediationProof ||
        row.actions.some(action => !action.requiresHumanReview))
      unacceptableClaims++;
    if (row.status === "REVIEW_POSSIBLE_ADVISORY" &&
        row.possibleIds.length === 0)
      issues.push("A positive association lacks a provider identifier.");
    if (row.status === "NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION" &&
        (row.possibleIds.length > 0 || row.unresolvedIds.length > 0 ||
          row.providerOnlyIds.length > 0))
      issues.push("A negative bounded result contains unresolved advisories.");
  }
  if (report.summary.examined <
      report.rows.length || report.totalRows <
      report.rows.length)
    issues.push("Report counts do not contain the displayed evidence.");
  if (!report.isReadOnly || report.changesCommitted ||
      report.providerQueried)
    issues.push("Action guidance incorrectly claims a mutating operation.");
  return {
    valid: issues.length === 0 &&
      missingEvidence === 0 && unacceptableClaims === 0,
    counted: report.rows.length,
    possibleOnPage: report.rows.filter(row =>
      row.status === "REVIEW_POSSIBLE_ADVISORY").length,
    missingEvidence, unacceptableClaims, reasons: issues,
  };
}
