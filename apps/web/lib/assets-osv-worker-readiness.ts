import { createHash } from "node:crypto";
import { db } from "@cyberpilot/database";
import { canManageWork, WorkInputError } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  parseOsvScheduleConfig, scheduleConsentDigest,
} from "./assets-osv-renewal-schedules";

/**
 * Readiness is deliberately diagnostic. This module does not grant a
 * machine identity, expose an unauthenticated dispatcher, or install cron.
 */
export type OsvWorkerReadinessPolicy = {
  maxSchedules: number;
  lookbackHours: number;
  staleClaimMinutes: number;
  maximumPendingPerOrg: number;
  requireNoStalledRuns: boolean;
  requireNoUnsettledQuota: boolean;
};
export type OsvWorkerReadinessEntry = {
  scheduleId: string;
  name: string;
  enabled: boolean;
  outboundConsent: boolean;
  nextDueAt: string;
  due: boolean;
  staleDue: boolean;
  revision: number;
  consentConsistent: boolean;
  activeInventory: boolean;
  blockingReasons: string[];
  eligibleForManualReview: boolean;
};
export type OsvWorkerReadinessReport = {
  schema: "cyberpilot.assets.osv.worker.readiness.v1";
  organizationId: string;
  checkedAt: string;
  policy: OsvWorkerReadinessPolicy;
  schedulesExamined: number;
  dueSchedules: number;
  consentedSchedules: number;
  blockedSchedules: number;
  stalledRunCount: number;
  unsettledQuotaCount: number;
  unknownRunCount: number;
  failureRunCount: number;
  quotaRequestsRemaining: number;
  quotaInspectionsRemaining: number;
  manualDispatchCandidates: OsvWorkerReadinessEntry[];
  automationReady: false;
  externalWorkerInstalled: false;
  warnings: string[];
  digest: string;
};
export type OsvWorkerIdentityPolicy = {
  schema: "cyberpilot.assets.osv.worker.identity.v1";
  actorType: "SERVICE";
  organizationId: string;
  permittedActions: string[];
  mayManageSchedules: false;
  mayOverrideQuota: false;
  mayAlterFindings: false;
  mayUpdateCyberScore: false;
  requiresOperationalActivation: true;
  requiresAuditedCredential: true;
  requiresTenantScoping: true;
  requiresSignedDispatch: true;
  maximumClaimsPerPoll: number;
  maximumParallelClaimsPerTenant: number;
};
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input))
    return invalid("Worker readiness policy must be an object.");
  return input as Record<string, unknown>;
}
function int(value: unknown, field: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    return invalid("Invalid worker readiness " + field + ".");
  return value;
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseOsvWorkerReadinessPolicy(
  input: unknown = {},
): OsvWorkerReadinessPolicy {
  const raw = object(input);
  if (Object.keys(raw).some(key => ![
    "maxSchedules", "lookbackHours", "staleClaimMinutes",
    "maximumPendingPerOrg", "requireNoStalledRuns",
    "requireNoUnsettledQuota",
  ].includes(key))) invalid("Unexpected worker readiness field.");
  for (const key of ["requireNoStalledRuns", "requireNoUnsettledQuota"])
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      invalid("Invalid worker readiness flag: " + key);
  return {
    maxSchedules: int(raw.maxSchedules ?? 50, "schedule limit", 1, 50),
    lookbackHours: int(raw.lookbackHours ?? 168, "lookback", 1, 720),
    staleClaimMinutes: int(raw.staleClaimMinutes ?? 30,
      "claim age", 15, 10080),
    maximumPendingPerOrg: int(raw.maximumPendingPerOrg ?? 1,
      "pending work", 1, 10),
    requireNoStalledRuns: raw.requireNoStalledRuns !== false,
    requireNoUnsettledQuota: raw.requireNoUnsettledQuota !== false,
  };
}
export function hypotheticalWorkerIdentity(
  organizationId: string,
): OsvWorkerIdentityPolicy {
  if (!/^[a-zA-Z0-9_-]{8,150}$/.test(organizationId))
    invalid("Invalid worker identity organization scope.");
  return {
    schema: "cyberpilot.assets.osv.worker.identity.v1",
    actorType: "SERVICE", organizationId,
    permittedActions: [
      "assets.osv.schedule.due.read",
      "assets.osv.schedule.slot.claim",
      "assets.osv.schedule.result.record",
      "assets.osv.quota.reserve",
    ],
    mayManageSchedules: false, mayOverrideQuota: false,
    mayAlterFindings: false, mayUpdateCyberScore: false,
    requiresOperationalActivation: true,
    requiresAuditedCredential: true,
    requiresTenantScoping: true, requiresSignedDispatch: true,
    maximumClaimsPerPoll: 1,
    maximumParallelClaimsPerTenant: 1,
  };
}
export type WorkerScheduleSnapshot = {
  id: string;
  name: string;
  enabled: boolean;
  outboundConsent: boolean;
  consentedAt: Date | null;
  nextDueAt: Date;
  cadenceMinutes: number;
  revision: number;
  consentDigest: string;
  inventoryImportId: string;
};
export function evaluateWorkerSchedule(
  schedule: WorkerScheduleSnapshot,
  now: Date, activeInventory: boolean,
  consentConsistent: boolean,
  stalled: number, unsettled: number,
  policy: OsvWorkerReadinessPolicy,
): OsvWorkerReadinessEntry {
  const blockers: string[] = [];
  const due = schedule.nextDueAt.getTime() <= now.getTime();
  const staleDue = schedule.nextDueAt.getTime() <
    now.getTime() - 30 * 86400000;
  if (!schedule.enabled)
    blockers.push("Schedule is disabled.");
  if (!schedule.outboundConsent || !schedule.consentedAt)
    blockers.push("No current explicit outbound consent.");
  if (!consentConsistent)
    blockers.push("Stored schedule authorization does not match its configuration.");
  if (!activeInventory)
    blockers.push("Original inventory is missing or retired.");
  if (!due)
    blockers.push("Scheduled interval is not yet due.");
  if (staleDue)
    blockers.push("Scheduled interval is older than the maximum dispatch window.");
  if (policy.requireNoStalledRuns && stalled > 0)
    blockers.push("Unsettled or expired schedule claims require incident review.");
  if (policy.requireNoUnsettledQuota && unsettled > 0)
    blockers.push("Unsettled provider quota reservations need investigation.");
  return {
    scheduleId: schedule.id, name: schedule.name,
    enabled: schedule.enabled, outboundConsent: schedule.outboundConsent,
    nextDueAt: schedule.nextDueAt.toISOString(),
    due, staleDue, revision: schedule.revision,
    consentConsistent, activeInventory,
    blockingReasons: blockers,
    eligibleForManualReview: blockers.length === 0,
  };
}
export async function inspectOsvWorkerReadiness(
  scope: AssetScope, input: unknown = {}, now = new Date(),
): Promise<OsvWorkerReadinessReport> {
  if (!canManageWork(scope.role))
    throw new WorkInputError("FORBIDDEN",
      "Only tenant administrators can inspect worker readiness.");
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid worker readiness time.");
  const policy = parseOsvWorkerReadinessPolicy(input);
  const windowStart = new Date(now.getTime() -
    policy.lookbackHours * 3600000);
  const day = new Date(Date.UTC(now.getUTCFullYear(),
    now.getUTCMonth(), now.getUTCDate()));
  const [schedules, claims, quotas, dailyQuota] = await Promise.all([
    db.assetOsvRenewalSchedule.findMany({
      where: { organizationId: scope.organizationId },
      take: policy.maxSchedules + 1,
      orderBy: [{ nextDueAt: "asc" }, { id: "asc" }],
    }),
    db.assetOsvRenewalRun.findMany({
      where: {
        organizationId: scope.organizationId,
        OR: [
          { state: "CLAIMED" },
          { state: { in: ["FAILED", "UNKNOWN"] },
            claimedAt: { gte: windowStart } },
        ],
      },
      take: 10001,
      select: { state: true, claimExpiresAt: true },
    }),
    db.assetOsvQuotaReservation.findMany({
      where: {
        organizationId: scope.organizationId, state: "RESERVED",
      },
      take: 10001,
      select: { id: true },
    }),
    db.assetOsvQuotaDay.findUnique({
      where: { organizationId_utcDay: {
        organizationId: scope.organizationId, utcDay: day,
      } },
    }),
  ]);
  if (schedules.length > policy.maxSchedules ||
      claims.length > 10000 || quotas.length > 10000)
    throw new WorkInputError("CONFLICT",
      "Worker readiness dataset exceeds safe bounded collection capacity.");
  const imports = await db.assetInventoryImport.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: schedules.map(s => s.inventoryImportId) },
    },
    select: { id: true, state: true },
  });
  const active = new Set(imports.filter(x =>
    x.state === "COMMITTED").map(x => x.id));
  const stalled = claims.filter(x =>
    x.state === "CLAIMED" && x.claimExpiresAt.getTime() <
      now.getTime() - policy.staleClaimMinutes * 60000).length;
  const unknown = claims.filter(x => x.state === "UNKNOWN").length;
  const failed = claims.filter(x => x.state === "FAILED").length;
  const candidates: OsvWorkerReadinessEntry[] = [];
  for (const schedule of schedules) {
    // Reconstruct the canonical consent-bearing policy. Never mistake a
    // merely well-formed SHA-256 for proof of schedule authorization.
    let consistent = false;
    try {
      const config = parseOsvScheduleConfig({
        name: schedule.name,
        inventoryImportId: schedule.inventoryImportId,
        sourceInspectionId: schedule.sourceInspectionId,
        cadenceMinutes: schedule.cadenceMinutes,
        inspection: schedule.inspection,
        policy: schedule.policy,
        allowNewPackages: schedule.allowNewPackages,
        allowIncompleteInventory: schedule.allowIncompleteInventory,
      });
      consistent = scheduleConsentDigest(
        scope.organizationId, config) === schedule.consentDigest;
    } catch {
      consistent = false;
    }
    candidates.push(evaluateWorkerSchedule(
      schedule, now, active.has(schedule.inventoryImportId),
      consistent, stalled, quotas.length, policy));
  }
  const canonical = {
    schema: "cyberpilot.assets.osv.worker.readiness.v1" as const,
    organizationId: scope.organizationId,
    checkedAt: now.toISOString(), policy,
    schedulesExamined: candidates.length,
    dueSchedules: candidates.filter(x => x.due).length,
    consentedSchedules: candidates.filter(x =>
      x.enabled && x.outboundConsent).length,
    blockedSchedules: candidates.filter(x =>
      x.blockingReasons.length > 0).length,
    stalledRunCount: stalled,
    unsettledQuotaCount: quotas.length,
    unknownRunCount: unknown,
    failureRunCount: failed,
    quotaRequestsRemaining: dailyQuota ?
      Math.max(0, dailyQuota.requestLimit -
        dailyQuota.requestsReserved) : 200,
    quotaInspectionsRemaining: dailyQuota ?
      Math.max(0, dailyQuota.inspectionLimit -
        dailyQuota.inspectionsReserved) : 20,
    manualDispatchCandidates: candidates,
    automationReady: false as const,
    externalWorkerInstalled: false as const,
  };
  return {
    ...canonical, digest: hash(canonical),
    warnings: [
      "This diagnostic does not install a scheduler or grant a service credential.",
      "Consent is validated authoritatively during dispatch; this report is only a preliminary check.",
      "Worker identity, signed dispatch, delivery alerts and LIVE acceptance are not implemented.",
      "Per-tenant and UTC-day quota counters never authorize bypassing OSV provider limits.",
      "Readiness data cannot establish that any endpoint is safe or patched.",
    ],
  };
}
