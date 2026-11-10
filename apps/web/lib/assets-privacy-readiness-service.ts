import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  parsePrivacyPolicy, assessPrivacyReadiness,
} from "./assets-privacy-readiness";
import type {
  PrivacyDataset, PrivacyImport, PrivacyPolicy,
  PrivacyReadinessReport,
} from "./assets-privacy-readiness";

export type PrivacyInspectionCommand = {
  policy: PrivacyPolicy;
};
function inputObject(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID",
      "Privacy inspection request must be a JSON object.");
  return value as Record<string, unknown>;
}
export function parsePrivacyInspectionCommand(input: unknown = {}):
  PrivacyInspectionCommand {
  const data = inputObject(input);
  if (Object.keys(data).some(key => key !== "policy"))
    throw new WorkInputError("INVALID",
      "Unexpected privacy inspection field.");
  return { policy: parsePrivacyPolicy(data.policy ?? {}) };
}
export async function inspectAssetPrivacyReadiness(
  scope: AssetScope, request: unknown = {},
  now = new Date(),
): Promise<PrivacyReadinessReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Privacy readiness requires organization administrator access.");
  if (!Number.isFinite(now.getTime()))
    throw new WorkInputError("INVALID",
      "Invalid privacy evaluation timestamp.");
  const { policy } = parsePrivacyInspectionCommand(request);
  const where = { organizationId: scope.organizationId };
  const [totalImports, imports, devices, inspections,
    cases, openCases, schedules,
    auditRecords, auditWithUser, auditWithResource] =
    await Promise.all([
      db.assetInventoryImport.count({ where }),
      db.assetInventoryImport.findMany({
        where, orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        take: policy.maxImports + 1,
        select: {
          id: true, organizationId: true,
          state: true, sourceLabel: true,
          createdAt: true, retiredAt: true,
          importedCount: true, payloadDigest: true,
        },
      }),
      db.assetInventoryDevice.groupBy({
        by: ["importId"], where,
        _count: { _all: true, hostname: true, ownerHash: true },
      }),
      db.assetOsvInspection.groupBy({
        by: ["inventoryImportId"], where,
        _count: { _all: true },
        _min: { completedAt: true },
        _max: { completedAt: true },
      }),
      db.assetAdviceCase.groupBy({
        by: ["importId"], where,
        _count: { _all: true },
      }),
      db.assetAdviceCase.groupBy({
        by: ["importId"],
        where: { ...where, status: { in: ["OPEN", "IN_REVIEW"] } },
        _count: { _all: true },
        _min: { openedAt: true },
      }),
      db.assetOsvRenewalSchedule.groupBy({
        by: ["inventoryImportId"], where,
        _count: { _all: true },
      }),
      db.auditEvent.count({
        where: {
          ...where, action: { startsWith: "assets." },
        },
      }),
      db.auditEvent.count({
        where: {
          ...where, action: { startsWith: "assets." },
          actorUserId: { not: null },
        },
      }),
      db.auditEvent.count({
        where: {
          ...where, action: { startsWith: "assets." },
          resourceId: { not: null },
        },
      }),
    ]);
  if (totalImports > policy.maxImports ||
      imports.length !== totalImports)
    throw new WorkInputError("CONFLICT",
      "Privacy readiness requires a complete bounded import set.");
  const devicesByImport = new Map(devices.map(row => [row.importId, row]));
  const inspectionsByImport = new Map(inspections.map(row =>
    [row.inventoryImportId, row]));
  const casesByImport = new Map(cases.map(row =>
    [row.importId, row]));
  const openByImport = new Map(openCases.map(row =>
    [row.importId, row]));
  const schedulesByImport = new Map(schedules.map(row =>
    [row.inventoryImportId, row]));
  const normalized: PrivacyImport[] = imports.map(row => {
    const observed = devicesByImport.get(row.id);
    const inspection = inspectionsByImport.get(row.id);
    const advice = casesByImport.get(row.id);
    const activeCases = openByImport.get(row.id);
    const schedule = schedulesByImport.get(row.id);
    return {
      importId: row.id, state: row.state,
      sourceLabel: row.sourceLabel,
      createdAt: row.createdAt, retiredAt: row.retiredAt,
      importedCount: row.importedCount,
      payloadDigest: row.payloadDigest,
      hostnamesPresent: observed?._count.hostname ?? 0,
      ownerHashesPresent: observed?._count.ownerHash ?? 0,
      deviceCount: observed?._count._all ?? 0,
      inspectionCount: inspection?._count._all ?? 0,
      oldestInspectionAt: inspection?._min.completedAt ?? null,
      newestInspectionAt: inspection?._max.completedAt ?? null,
      caseCount: advice?._count._all ?? 0,
      openedCaseCount: activeCases?._count._all ?? 0,
      oldestOpenCaseAt: activeCases?._min.openedAt ?? null,
      scheduleCount: schedule?._count._all ?? 0,
    };
  });
  const dataset: PrivacyDataset = {
    organizationId: scope.organizationId,
    imports: normalized, totalImports, now,
    auditRecords, auditWithUser, auditWithResource,
  };
  return assessPrivacyReadiness(dataset, policy);
}
