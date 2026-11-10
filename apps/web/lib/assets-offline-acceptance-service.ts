import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import { parseAssetAdviceInput } from "./assets-action-guidance";
import { readAssetAdviceSnapshot } from "./assets-action-guidance-service";
import { evaluateAssetOfflineAcceptance, parseAcceptancePolicy } from "./assets-offline-acceptance";
import type { AcceptanceDataset, AcceptancePolicy, AcceptanceReport } from "./assets-offline-acceptance";
import type { AssetScope } from "./assets-inventory-service";
import type { CaseRow } from "./assets-action-case-service";

export type OfflineAcceptanceRequest = {
  importId: string;
  inspectionId: string;
  bindings: unknown;
  policy: AcceptancePolicy;
};
function error(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    error("Offline acceptance input must be an object.");
  return input as Record<string, unknown>;
}
export function parseOfflineAcceptanceRequest(input: unknown): OfflineAcceptanceRequest {
  const raw = object(input);
  if (Object.keys(raw).some(key => !["importId", "inspectionId", "bindings", "policy"].includes(key)))
    error("Unsupported offline acceptance request field.");
  const guidance = parseAssetAdviceInput({
    importId: raw.importId, inspectionId: raw.inspectionId,
    bindings: raw.bindings, limit: 1,
  });
  return {
    importId: guidance.importId,
    inspectionId: guidance.inspectionId,
    bindings: guidance.bindings,
    policy: parseAcceptancePolicy(raw.policy ?? {}),
  };
}
function caseView(value: {
  id: string; organizationId: string; importId: string; inspectionId: string;
  evidenceFingerprint: string; inventoryDigest: string; inspectionDigest: string;
  externalId: string; normalizedProductKey: string; softwareVersion: string | null;
  status: string; category: string; priority: string; revision: number;
  title: string; rationale: unknown; actions: unknown; advisoryIds: unknown;
  openedAt: Date; lastDecisionAt: Date | null;
  lastDecisionReason: string | null; lastDecisionUserId: string | null;
  steps: Array<{
    id: string; actionCode: string; status: string; revision: number;
    note: string | null; completedAt: Date | null; completedByUserId: string | null;
  }>;
}): CaseRow {
  return {
    ...value,
    status: value.status as CaseRow["status"],
    steps: value.steps.map(step => ({
      ...step, status: step.status as CaseRow["steps"][number]["status"],
      completedAt: step.completedAt?.toISOString() ?? null,
    })),
    openedAt: value.openedAt.toISOString(),
    lastDecisionAt: value.lastDecisionAt?.toISOString() ?? null,
  };
}
/**
 * A tenant-scoped read-only operational acceptance preview.
 * No arbitrary SQL, no writes, no provider fetch, no cross-tenant joins.
 */
export async function inspectAssetOfflineAcceptance(
  scope: AssetScope, raw: unknown,
  now = new Date(),
): Promise<AcceptanceReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only organization administrators can inspect release readiness.");
  if (!Number.isFinite(now.getTime()))
    throw new WorkInputError("INVALID", "Invalid acceptance evaluation clock.");
  const request = parseOfflineAcceptanceRequest(raw);
  const input = parseAssetAdviceInput({
    importId: request.importId, inspectionId: request.inspectionId,
    bindings: request.bindings, limit: 1,
  });
  const snapshot = await readAssetAdviceSnapshot(scope, input);
  const where = {
    organizationId: scope.organizationId,
    importId: request.importId,
    inspectionId: request.inspectionId,
  };
  const [totalCases, rows] = await Promise.all([
    db.assetAdviceCase.count({ where }),
    db.assetAdviceCase.findMany({
      where, orderBy: [{ id: "asc" }],
      take: request.policy.maxCases + 1,
      include: { steps: { orderBy: { actionCode: "asc" } } },
    }),
  ]);
  if (totalCases > request.policy.maxCases || rows.length !== totalCases)
    throw new WorkInputError("CONFLICT",
      "Acceptance report requires every case; narrow its source or increase bounded capacity.");
  const caseIds = rows.map(row => row.id);
  const auditRows = caseIds.length ?
    await db.auditEvent.findMany({
      where: {
        organizationId: scope.organizationId,
        resourceType: "AssetAdviceCase",
        resourceId: { in: caseIds },
      },
      select: { resourceId: true }, distinct: ["resourceId"],
      take: request.policy.maxCases + 1,
    }) : [];
  const dataset: AcceptanceDataset = {
    snapshot, bindings: input.bindings,
    organizationId: scope.organizationId,
    checkedAt: now, cases: rows.map(caseView),
    auditCaseIds: auditRows.flatMap(row => row.resourceId ? [row.resourceId] : []),
  };
  return evaluateAssetOfflineAcceptance(dataset, request.policy);
}
