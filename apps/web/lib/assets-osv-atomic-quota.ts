import { createHash, randomUUID } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";

export const OSV_DEFAULT_DAILY_INSPECTION_LIMIT = 20;
export const OSV_DEFAULT_DAILY_REQUEST_LIMIT = 200;
export type OsvQuotaPolicy = {
  dailyInspectionLimit: number;
  dailyRequestLimit: number;
  maxReservedRequestsPerInspection: number;
};
export type OsvQuotaCommand = {
  requestKey: string;
  requestDigest: string;
  inventoryImportId: string;
  reservedRequests: number;
};
export type OsvReservationState = "RESERVED" | "FINISHED" | "FAILED" | "UNKNOWN";
export type OsvReservationTicket = {
  reservationId: string;
  organizationId: string;
  quotaDayId: string;
  utcDay: string;
  requestKey: string;
  requestDigest: string;
  inventoryImportId: string;
  reservedRequests: number;
  state: OsvReservationState;
  replayed: boolean;
  inspectionLimit: number;
  requestLimit: number;
  inspectionsReserved: number;
  requestsReserved: number;
};
export type OsvQuotaSnapshot = {
  schema: "cyberpilot.assets.osv.quota.snapshot.v1";
  organizationId: string;
  utcDay: string;
  inspectionLimit: number;
  requestLimit: number;
  inspectionsReserved: number;
  requestsReserved: number;
  inspectionsRemaining: number;
  requestsRemaining: number;
  reservations: Array<{
    reservationId: string;
    requestKey: string;
    inventoryImportId: string;
    state: string;
    reservedRequests: number;
    actualRequests: number;
    startedAt: string;
    finishedAt: string | null;
  }>;
  reservationsTotal: number;
  hasMore: boolean;
  warnings: string[];
};
const sha = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const isConflict = (cause: unknown, code: string) =>
  Boolean(cause && typeof cause === "object" &&
    "code" in cause && cause.code === code);
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
export function parseOsvQuotaPolicy(input: unknown = {}): OsvQuotaPolicy {
  if (!input || typeof input !== "object" || Array.isArray(input))
    invalid("OSV quota policy must be an object.");
  const raw = input as Record<string, unknown>;
  if (Object.keys(raw).some(key => ![
    "dailyInspectionLimit", "dailyRequestLimit",
    "maxReservedRequestsPerInspection",
  ].includes(key))) invalid("Unknown OSV quota policy property.");
  const integer = (key: string, fallback: number, max: number) => {
    const value = raw[key] ?? fallback;
    if (typeof value !== "number" || !Number.isSafeInteger(value) ||
        value < 1 || value > max)
      invalid("Invalid OSV quota policy: " + key);
    return value;
  };
  const result = {
    dailyInspectionLimit: integer("dailyInspectionLimit", 20, 100),
    dailyRequestLimit: integer("dailyRequestLimit", 200, 2000),
    maxReservedRequestsPerInspection: integer(
      "maxReservedRequestsPerInspection", 60, 100),
  };
  if (result.maxReservedRequestsPerInspection >
      result.dailyRequestLimit)
    invalid("Per-inspection request budget exceeds daily limit.");
  return result;
}
export function utcQuotaDay(now: Date): Date {
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid quota evaluation timestamp.");
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(),
    now.getUTCDate()));
}
export function parseOsvQuotaCommand(input: unknown,
  policy = parseOsvQuotaPolicy()): OsvQuotaCommand {
  if (!input || typeof input !== "object" || Array.isArray(input))
    invalid("OSV quota reservation must be an object.");
  const raw = input as Record<string, unknown>;
  if (Object.keys(raw).some(key => ![
    "requestKey", "requestDigest", "inventoryImportId", "reservedRequests",
  ].includes(key))) invalid("Unexpected quota reservation property.");
  const key = raw.requestKey;
  if (typeof key !== "string" || key.length < 12 ||
      key.length > 150 || /[\u0000-\u001f\u007f]/.test(key))
    invalid("Invalid OSV quota request key.");
  const requestDigest = raw.requestDigest;
  if (typeof requestDigest !== "string" ||
      !/^[a-f0-9]{64}$/.test(requestDigest))
    invalid("Invalid quota request digest.");
  const importId = raw.inventoryImportId;
  if (typeof importId !== "string" || importId.length < 8 ||
      importId.length > 150 || !/^[a-zA-Z0-9_-]+$/.test(importId))
    invalid("Invalid quota inventory import ID.");
  const count = raw.reservedRequests;
  if (typeof count !== "number" || !Number.isSafeInteger(count) ||
      count < 1 || count > policy.maxReservedRequestsPerInspection)
    invalid("OSV request reservation exceeds per-inspection limit.");
  return {
    requestKey: key, requestDigest,
    inventoryImportId: importId, reservedRequests: count,
  };
}
export function quotaReservationDigest(
  organizationId: string, command: OsvQuotaCommand,
): string {
  return sha({
    schema: "cyberpilot.assets.osv.quota.reservation.v1",
    organizationId,
    ...command,
  });
}
export function evaluateQuotaCapacity(
  counters: {
    inspectionsReserved: number;
    requestsReserved: number;
    inspectionLimit: number;
    requestLimit: number;
  }, requested: number,
): {
  allowed: boolean;
  remainingInspections: number;
  remainingRequests: number;
  reason: "AVAILABLE" | "INSPECTIONS_EXHAUSTED" | "REQUESTS_EXHAUSTED";
} {
  const remainingInspections = Math.max(0,
    counters.inspectionLimit - counters.inspectionsReserved);
  const remainingRequests = Math.max(0,
    counters.requestLimit - counters.requestsReserved);
  const reason = remainingInspections < 1 ?
    "INSPECTIONS_EXHAUSTED" :
    remainingRequests < requested ? "REQUESTS_EXHAUSTED" :
    "AVAILABLE";
  return {
    allowed: reason === "AVAILABLE",
    remainingInspections,
    remainingRequests, reason,
  };
}
export function computeReservedRequestPages(
  selectedPackages: number, maximumPagesPerPackage: number,
): number {
  if (!Number.isSafeInteger(selectedPackages) ||
      selectedPackages < 0 || selectedPackages > 20 ||
      !Number.isSafeInteger(maximumPagesPerPackage) ||
      maximumPagesPerPackage < 1 || maximumPagesPerPackage > 3)
    invalid("Invalid OSV planned provider request budget.");
  return selectedPackages * maximumPagesPerPackage;
}
type ReservationDatabaseRow = {
  id: string;
  organizationId: string;
  quotaDayId: string;
  requestKey: string;
  requestDigest: string;
  inventoryImportId: string;
  reservedRequests: number;
  state: string;
};
type DayDatabaseRow = {
  id: string; utcDay: Date;
  inspectionLimit: number; requestLimit: number;
  inspectionsReserved: number; requestsReserved: number;
};
function ticket(row: ReservationDatabaseRow, day: DayDatabaseRow,
  replayed = false): OsvReservationTicket {
  return {
    reservationId: row.id,
    organizationId: row.organizationId,
    quotaDayId: row.quotaDayId,
    utcDay: day.utcDay.toISOString().slice(0, 10),
    requestKey: row.requestKey,
    requestDigest: row.requestDigest,
    inventoryImportId: row.inventoryImportId,
    reservedRequests: row.reservedRequests,
    state: row.state as OsvReservationState,
    replayed,
    inspectionLimit: day.inspectionLimit,
    requestLimit: day.requestLimit,
    inspectionsReserved: day.inspectionsReserved,
    requestsReserved: day.requestsReserved,
  };
}
function assertSameReservation(
  row: ReservationDatabaseRow,
  organizationId: string,
  command: OsvQuotaCommand,
): void {
  if (row.organizationId !== organizationId ||
      row.requestDigest !== command.requestDigest ||
      row.inventoryImportId !== command.inventoryImportId ||
      row.reservedRequests !== command.reservedRequests)
    throw new WorkInputError("CONFLICT",
      "OSV reservation key already belongs to a different request.");
}
export async function reserveOfficialOsvQuota(
  scope: AssetScope, input: unknown,
  now = new Date(), policy = parseOsvQuotaPolicy(),
): Promise<OsvReservationTicket> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only administrators can reserve provider request quota.");
  const command = parseOsvQuotaCommand(input, policy);
  const day = utcQuotaDay(now);
  const unique = {
    organizationId_requestKey: {
      organizationId: scope.organizationId,
      requestKey: command.requestKey,
    },
  };
  const old = await db.assetOsvQuotaReservation.findUnique({
    where: unique, include: { quotaDay: true },
  });
  if (old) {
    assertSameReservation(old, scope.organizationId, command);
    return ticket(old, old.quotaDay, true);
  }
  // Create a single row per tenant/day first. Upsert uses the unique
  // (organizationId, utcDay) database constraint, not process-local state.
  const quota = await db.assetOsvQuotaDay.upsert({
    where: { organizationId_utcDay: {
      organizationId: scope.organizationId, utcDay: day,
    } },
    create: {
      organizationId: scope.organizationId,
      utcDay: day,
      inspectionLimit: policy.dailyInspectionLimit,
      requestLimit: policy.dailyRequestLimit,
    },
    update: {},
  });
  try {
    return await db.$transaction(async tx => {
      const previously = await tx.assetOsvQuotaReservation.findUnique({
        where: unique,
      });
      if (previously) {
        assertSameReservation(previously, scope.organizationId, command);
        const latestDay = await tx.assetOsvQuotaDay.findUniqueOrThrow({
          where: { id: previously.quotaDayId },
        });
        return ticket(previously, latestDay, true);
      }
      // A single atomic UPDATE ... WHERE enforces both limits under
      // concurrent transactions and survives multiple web workers.
      const charged = await tx.assetOsvQuotaDay.updateMany({
        where: {
          id: quota.id,
          organizationId: scope.organizationId,
          inspectionsReserved: { lt: quota.inspectionLimit },
          requestsReserved: {
            lte: quota.requestLimit - command.reservedRequests,
          },
        },
        data: {
          inspectionsReserved: { increment: 1 },
          requestsReserved: { increment: command.reservedRequests },
        },
      });
      if (charged.count !== 1)
        throw new WorkInputError("CONFLICT",
          "OSV provider daily atomic quota is exhausted.");
      const stored = await tx.assetOsvQuotaReservation.create({
        data: {
          organizationId: scope.organizationId,
          quotaDayId: quota.id,
          inventoryImportId: command.inventoryImportId,
          requestKey: command.requestKey,
          requestDigest: command.requestDigest,
          reservedRequests: command.reservedRequests,
          state: "RESERVED",
        },
      });
      const latestDay = await tx.assetOsvQuotaDay.findUniqueOrThrow({
        where: { id: quota.id },
      });
      return ticket(stored, latestDay);
    });
  } catch (cause) {
    if (isConflict(cause, "P2002")) {
      const previous = await db.assetOsvQuotaReservation.findUnique({
        where: unique, include: { quotaDay: true },
      });
      if (previous) {
        assertSameReservation(previous, scope.organizationId, command);
        return ticket(previous, previous.quotaDay, true);
      }
    }
    throw cause;
  }
}
export function classifyQuotaSettlement(
  current: string,
  desired: "FINISHED" | "FAILED",
  actualRequests: number, reservedRequests: number,
): {
  allowed: boolean;
  next: OsvReservationState;
  actualRequests: number;
  warning: string | null;
} {
  if (!Number.isSafeInteger(actualRequests) ||
      actualRequests < 0 || actualRequests > reservedRequests)
    invalid("Actual OSV requests must fit within the prior reservation.");
  if (current === "RESERVED")
    return {
      allowed: true, next: desired, actualRequests, warning: null,
    };
  if (current === desired)
    return {
      allowed: false, next: desired, actualRequests,
      warning: "The quota reservation was already settled.",
    };
  return {
    allowed: false, next: current as OsvReservationState,
    actualRequests,
    warning: "An existing terminal quota status cannot be overwritten.",
  };
}
export async function settleOfficialOsvQuota(
  scope: AssetScope,
  ticketValue: Pick<OsvReservationTicket,
    "reservationId" | "requestKey" | "requestDigest" | "reservedRequests">,
  state: "FINISHED" | "FAILED",
  actualRequests: number, now = new Date(),
): Promise<OsvReservationTicket> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Quota settlement denied.");
  utcQuotaDay(now);
  const settlement = classifyQuotaSettlement(
    "RESERVED", state, actualRequests, ticketValue.reservedRequests);
  if (!settlement.allowed)
    throw new WorkInputError("CONFLICT", "Invalid OSV settlement.");
  const changed = await db.assetOsvQuotaReservation.updateMany({
    where: {
      id: ticketValue.reservationId,
      organizationId: scope.organizationId,
      requestKey: ticketValue.requestKey,
      requestDigest: ticketValue.requestDigest,
      reservedRequests: ticketValue.reservedRequests,
      state: "RESERVED",
    },
    data: {
      state,
      actualRequests, finishedAt: now,
    },
  });
  const result = await db.assetOsvQuotaReservation.findFirst({
    where: {
      id: ticketValue.reservationId,
      organizationId: scope.organizationId,
      requestDigest: ticketValue.requestDigest,
    },
    include: { quotaDay: true },
  });
  if (!result)
    throw new WorkInputError("MISSING", "OSV quota reservation not found.");
  if (!changed.count && result.state !== state)
    throw new WorkInputError("CONFLICT",
      "Quota reservation has an incompatible terminal state.");
  if (result.actualRequests > result.reservedRequests)
    throw new WorkInputError("CONFLICT",
      "OSV reservation exceeds its reserved request count.");
  return ticket(result, result.quotaDay, changed.count === 0);
}
export async function inspectOfficialOsvQuota(
  scope: AssetScope, now = new Date(), limit = 50,
): Promise<OsvQuotaSnapshot> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only administrators may inspect provider request quota.");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    invalid("Invalid quota reservation page limit.");
  const day = utcQuotaDay(now);
  const current = await db.assetOsvQuotaDay.findUnique({
    where: { organizationId_utcDay: {
      organizationId: scope.organizationId,
      utcDay: day,
    } },
  });
  const policy = parseOsvQuotaPolicy();
  const quota = current ?? {
    inspectionLimit: policy.dailyInspectionLimit,
    requestLimit: policy.dailyRequestLimit,
    inspectionsReserved: 0, requestsReserved: 0,
  };
  const reservations = current ?
    await db.assetOsvQuotaReservation.findMany({
      where: {
        organizationId: scope.organizationId,
        quotaDayId: current.id,
      },
      orderBy: [{ startedAt: "desc" }, { id: "desc" }],
      take: limit,
      select: {
        id: true, requestKey: true, inventoryImportId: true,
        state: true, reservedRequests: true, actualRequests: true,
        startedAt: true, finishedAt: true,
      },
    }) : [];
  return {
    schema: "cyberpilot.assets.osv.quota.snapshot.v1",
    organizationId: scope.organizationId,
    utcDay: day.toISOString().slice(0, 10),
    inspectionLimit: quota.inspectionLimit,
    requestLimit: quota.requestLimit,
    inspectionsReserved: quota.inspectionsReserved,
    requestsReserved: quota.requestsReserved,
    inspectionsRemaining: Math.max(0,
      quota.inspectionLimit - quota.inspectionsReserved),
    requestsRemaining: Math.max(0,
      quota.requestLimit - quota.requestsReserved),
    reservations: reservations.map(row => ({
      reservationId: row.id, requestKey: row.requestKey,
      inventoryImportId: row.inventoryImportId,
      state: row.state, reservedRequests: row.reservedRequests,
      actualRequests: row.actualRequests,
      startedAt: row.startedAt.toISOString(),
      finishedAt: row.finishedAt?.toISOString() ?? null,
    })),
    reservationsTotal: quota.inspectionsReserved,
    hasMore: quota.inspectionsReserved > reservations.length,
    warnings: [
      "Provider requests are charged BEFORE network access under an atomic PostgreSQL limit.",
      "Reserved requests are not automatically refunded on network failure.",
      "Reservations left RESERVED after an interrupted worker stay charged and require investigation.",
      "This is a per-organization UTC-day application quota, not a guarantee of upstream OSV.dev capacity.",
      "Quota reservations do not certify endpoint exposure or remediation.",
    ],
  };
}
export function createOsvQuotaCommand(
  organizationId: string, inventoryImportId: string,
  selectedPackages: number, maximumPagesPerPackage: number,
  providedKey?: string,
): OsvQuotaCommand {
  const reservedRequests =
    computeReservedRequestPages(selectedPackages, maximumPagesPerPackage);
  if (reservedRequests < 1)
    invalid("There are no provider queries to reserve.");
  const requestKey = providedKey ?? "osv-provider-" + randomUUID();
  const requestDigest = sha({
    schema: "cyberpilot.assets.osv.quota.command.v1",
    organizationId, inventoryImportId,
    selectedPackages, maximumPagesPerPackage,
    requestKey,
  });
  return {
    requestKey, requestDigest, inventoryImportId, reservedRequests,
  };
}
