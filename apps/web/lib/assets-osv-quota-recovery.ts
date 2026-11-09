import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import { utcQuotaDay } from "./assets-osv-atomic-quota";

export type OsvQuotaRecoveryPolicy = {
  minimumAgeMinutes: number;
  maximumListed: number;
};
export type OsvStalledReservation = {
  id: string;
  requestKey: string;
  inventoryImportId: string;
  startedAt: string;
  ageMinutes: number;
  reservedRequests: number;
  state: string;
  eligible: boolean;
  reason: string;
};
export type OsvQuotaRecoveryPreview = {
  schema: "cyberpilot.assets.osv.quota.recovery.preview.v1";
  organizationId: string;
  generatedAt: string;
  minimumAgeMinutes: number;
  totalStalled: number;
  inspected: number;
  eligible: number;
  incomplete: boolean;
  reservations: OsvStalledReservation[];
  digest: string;
  warnings: string[];
};
export type OsvQuotaRecoveryCommand = {
  reservationId: string;
  confirmReservationId: string;
  expectedRequestDigest: string;
  minimumAgeMinutes: number;
  reason: string;
};
export type OsvQuotaRecoveryResult = {
  schema: "cyberpilot.assets.osv.quota.recovery.v1";
  organizationId: string;
  reservationId: string;
  state: "UNKNOWN";
  changed: boolean;
  reservedRequests: number;
  effectiveRefund: 0;
  auditedAt: string;
  digest: string;
  warnings: string[];
};
function failure(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return failure("Expected OSV recovery object.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, low: number, high: number, name: string) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < low || value > high)
    return failure("Invalid recovery " + name + ".");
  return value;
}
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseOsvQuotaRecoveryPolicy(
  input: unknown = {},
): OsvQuotaRecoveryPolicy {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "minimumAgeMinutes", "maximumListed",
  ].includes(key)))
    failure("Unknown OSV recovery policy.");
  return {
    minimumAgeMinutes: integer(raw.minimumAgeMinutes ?? 30,
      15, 43200, "minimum age"),
    maximumListed: integer(raw.maximumListed ?? 50,
      1, 100, "maximum listed"),
  };
}
export function parseOsvQuotaRecoveryCommand(
  input: unknown,
): OsvQuotaRecoveryCommand {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "reservationId", "confirmReservationId", "expectedRequestDigest",
    "minimumAgeMinutes", "reason",
  ].includes(key)))
    failure("Unknown OSV recovery command.");
  const id = raw.reservationId;
  const confirmation = raw.confirmReservationId;
  if (typeof id !== "string" || id.length < 8 ||
      id.length > 150 || !/^[a-zA-Z0-9_-]+$/.test(id) ||
      confirmation !== id)
    failure("Confirm the exact OSV reservation ID.");
  const expected = raw.expectedRequestDigest;
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/.test(expected))
    failure("Invalid expected quota reservation digest.");
  const reason = raw.reason;
  if (typeof reason !== "string" || reason.trim().length < 20 ||
      reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason))
    failure("A detailed human recovery reason is required.");
  return {
    reservationId: id,
    confirmReservationId: id,
    expectedRequestDigest: expected,
    minimumAgeMinutes: integer(raw.minimumAgeMinutes ?? 30,
      15, 43200, "minimum age"),
    reason: reason.trim(),
  };
}
export function assessStalledReservation(
  row: {
    id: string; requestKey: string; inventoryImportId: string;
    state: string; startedAt: Date; reservedRequests: number;
  }, now: Date, thresholdMinutes: number,
): OsvStalledReservation {
  const age = (now.getTime() - row.startedAt.getTime()) / 60000;
  const valid = Number.isFinite(age) && age >= 0;
  const eligible = row.state === "RESERVED" &&
    valid && age >= thresholdMinutes;
  return {
    id: row.id, requestKey: row.requestKey,
    inventoryImportId: row.inventoryImportId,
    startedAt: row.startedAt.toISOString(),
    ageMinutes: valid ? Math.floor(age) : -1,
    reservedRequests: row.reservedRequests,
    state: row.state, eligible,
    reason: row.state !== "RESERVED" ?
      "The reservation is already terminal." :
      !valid ? "The recorded start time is invalid or in the future." :
      !eligible ? "The configured interruption investigation delay has not elapsed." :
      "Reservation has remained unsettled beyond the investigation delay.",
  };
}
export async function previewOsvQuotaRecovery(
  scope: AssetScope, input: unknown,
  now = new Date(),
): Promise<OsvQuotaRecoveryPreview> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "OSV quota recovery requires administrator permission.");
  const policy = parseOsvQuotaRecoveryPolicy(input);
  utcQuotaDay(now);
  const rows = await db.assetOsvQuotaReservation.findMany({
    where: {
      organizationId: scope.organizationId,
      state: "RESERVED",
    },
    orderBy: [{ startedAt: "asc" }, { id: "asc" }],
    take: policy.maximumListed + 1,
    select: {
      id: true, requestKey: true, inventoryImportId: true,
      state: true, startedAt: true, reservedRequests: true,
    },
  });
  const [count] = await Promise.all([
    db.assetOsvQuotaReservation.count({
      where: { organizationId: scope.organizationId, state: "RESERVED" },
    }),
  ]);
  const inspected = rows.slice(0, policy.maximumListed)
    .map(row => assessStalledReservation(
      row, now, policy.minimumAgeMinutes));
  const canonical = {
    schema: "cyberpilot.assets.osv.quota.recovery.preview.v1" as const,
    organizationId: scope.organizationId,
    generatedAt: now.toISOString(),
    minimumAgeMinutes: policy.minimumAgeMinutes,
    totalStalled: count, inspected: inspected.length,
    eligible: inspected.filter(row => row.eligible).length,
    incomplete: count > inspected.length,
    reservations: inspected,
  };
  return {
    ...canonical, digest: sha(canonical),
    warnings: [
      "An unsettled reservation may have sent traffic to the upstream provider.",
      "This preview does not change quota counters or reservation status.",
      "Manual UNKNOWN classification does not refund reserved quota.",
      "A reservation cannot be re-executed with the same key after it was started.",
    ],
  };
}
export async function markStalledOsvQuotaUnknown(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<OsvQuotaRecoveryResult> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "OSV quota recovery requires administrator permission.");
  const command = parseOsvQuotaRecoveryCommand(input);
  utcQuotaDay(now);
  const cutoff = new Date(now.getTime() -
    command.minimumAgeMinutes * 60000);
  const found = await db.assetOsvQuotaReservation.findFirst({
    where: {
      id: command.reservationId,
      organizationId: scope.organizationId,
    },
  });
  if (!found)
    throw new WorkInputError("MISSING", "Quota reservation not found.");
  if (found.requestDigest !== command.expectedRequestDigest)
    throw new WorkInputError("CONFLICT",
      "Quota reservation digest changed; inspect the current record.");
  if (found.state === "UNKNOWN") {
    const canonical = {
      schema: "cyberpilot.assets.osv.quota.recovery.v1" as const,
      organizationId: scope.organizationId,
      reservationId: found.id, state: "UNKNOWN" as const,
      changed: false, reservedRequests: found.reservedRequests,
      effectiveRefund: 0 as const, auditedAt: now.toISOString(),
    };
    return { ...canonical, digest: sha(canonical), warnings: [
      "This reservation was previously classified as UNKNOWN.",
      "No reserved quota was refunded.",
    ] };
  }
  if (found.state !== "RESERVED" || found.startedAt > cutoff)
    throw new WorkInputError("CONFLICT",
      "Only sufficiently old unsettled reservations can be marked UNKNOWN.");
  const updated = await db.$transaction(async tx => {
    const changed = await tx.assetOsvQuotaReservation.updateMany({
      where: {
        id: found.id,
        organizationId: scope.organizationId,
        requestDigest: command.expectedRequestDigest,
        state: "RESERVED", startedAt: { lte: cutoff },
      },
      data: {
        state: "UNKNOWN", finishedAt: now,
        errorCode: "WORKER_OUTCOME_UNKNOWN",
      },
    });
    if (changed.count !== 1)
      throw new WorkInputError("CONFLICT",
        "Quota reservation changed during recovery.");
    await tx.auditEvent.create({
      data: {
        organizationId: scope.organizationId,
        actorType: "USER", actorUserId: scope.userId,
        action: "assets.osv.quota.reservation.unknown",
        resourceType: "AssetOsvQuotaReservation", resourceId: found.id,
        metadata: {
          schema: "cyberpilot.assets.osv.quota.recovery.audit.v1",
          reason: command.reason,
          reservedRequests: found.reservedRequests,
          requestDigest: found.requestDigest,
          refunded: false,
          state: "UNKNOWN",
        },
      },
    });
    return changed.count;
  });
  const canonical = {
    schema: "cyberpilot.assets.osv.quota.recovery.v1" as const,
    organizationId: scope.organizationId,
    reservationId: found.id,
    state: "UNKNOWN" as const, changed: updated === 1,
    reservedRequests: found.reservedRequests,
    effectiveRefund: 0 as const,
    auditedAt: now.toISOString(),
  };
  return {
    ...canonical, digest: sha(canonical),
    warnings: [
      "The upstream network outcome remains unknown.",
      "Reserved quota remains charged. No refund or retry was performed.",
      "The action is recorded in the tenant audit log.",
    ],
  };
}
