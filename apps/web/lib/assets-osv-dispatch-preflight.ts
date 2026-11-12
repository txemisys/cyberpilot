import { createHash, randomUUID } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import type { AssetScope } from "./assets-inventory-service";
import {
  configuredDispatchKeys, parseSignedDispatchIntent,
  signOsvDispatch, verifySignedDispatch, inspectDispatchConfiguration,
} from "./assets-osv-signed-dispatch";
import type {
  DispatchKeyConfig, SignedDispatchIntent, VerifiedDispatch,
} from "./assets-osv-signed-dispatch";
import {
  parseOsvScheduleConfig, scheduleConsentDigest,
  nextOsvDueAt,
} from "./assets-osv-renewal-schedules";

export type OsvDispatchPreflightPolicy = {
  maxSchedules: number;
  maximumObservations: number;
  requireNoOpenCriticalIncidents: boolean;
  requireNoUnsettledClaims: boolean;
  requireNoUnsettledQuotas: boolean;
  requireFreshInventory: boolean;
  inspectSignatureAuthentication: boolean;
  minimumRemainingRequests: number;
  minimumRemainingInspections: number;
};
export type OsvDispatchPreflightInput = {
  scheduleId: string | null;
  policy: OsvDispatchPreflightPolicy;
};
export type OsvDispatchPreflightCheck = {
  id: string;
  level: "PASS" | "BLOCK" | "WARN";
  category: "IDENTITY" | "CONSENT" | "INVENTORY" | "DUE" |
    "QUOTA" | "CLAIMS" | "INCIDENTS" | "INTEGRITY" | "PROTOCOL";
  summary: string;
  evidence: string | number | boolean | null;
  required: boolean;
};
export type OsvDispatchPreflightSchedule = {
  scheduleId: string;
  scheduleName: string;
  revision: number;
  enabled: boolean;
  consented: boolean;
  inventoryImportId: string;
  dueAt: string;
  nextDueAt: string;
  canConsiderManualDispatch: boolean;
  authorizingKeyIds: string[];
  checks: OsvDispatchPreflightCheck[];
  blocked: number;
  warnings: number;
  passed: number;
};
export type OsvDispatchPreflightReport = {
  schema: "cyberpilot.assets.osv.dispatch.preflight.v1";
  organizationId: string;
  evaluatedAt: string;
  policy: OsvDispatchPreflightPolicy;
  selectedScheduleId: string | null;
  totalSchedules: number;
  scannedSchedules: number;
  truncated: boolean;
  blockedSchedules: number;
  manuallyReviewableSchedules: number;
  remainingRequests: number;
  remainingInspections: number;
  quotaReservationsOpen: number;
  claimsOpen: number;
  criticalIncidentsOpen: number;
  keysEnabled: boolean;
  previewOnly: true;
  outboundRequests: 0;
  noncesConsumed: 0;
  cronInstalled: false;
  schedules: OsvDispatchPreflightSchedule[];
  warnings: string[];
  digest: string;
};
export type OsvDispatchChallenge = {
  schema: "cyberpilot.assets.osv.dispatch.challenge.v1";
  organizationId: string;
  scheduleId: string;
  scheduleRevision: number;
  keyId: string;
  issuedAt: string;
  expiresAt: string;
  protocolMatched: boolean;
  crossTenantRejected: boolean;
  signatureMutationRejected: boolean;
  expiredRejected: boolean;
  replayStoragePresent: boolean;
  authenticationAccepted: boolean;
  signedRequestSent: false;
  noncePersisted: false;
  providerContacted: false;
  scheduleChanged: false;
  warnings: string[];
};
const schema = "cyberpilot.assets.osv.dispatch.preflight.v1" as const;
function bad(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function forbidden(message: string): never {
  throw new WorkInputError("FORBIDDEN", message);
}
function requireScope(scope: AssetScope) {
  if (!canManageWork(scope.role))
    forbidden("Only organization administrators may preview signed dispatch.");
}
function record(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    bad("Dispatch preflight request must be a JSON object.");
  return input as Record<string, unknown>;
}
function integer(value: unknown, label: string, minimum: number,
  maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < minimum || value > maximum)
    bad("Invalid dispatch preflight " + label + ".");
  return value;
}
function boolean(raw: Record<string, unknown>, key: string, defaultValue: boolean) {
  const value = raw[key] ?? defaultValue;
  if (typeof value !== "boolean")
    bad("Dispatch preflight " + key + " must be boolean.");
  return value;
}
function digest(input: unknown) {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
export function parsePreflightPolicy(input: unknown = {}):
  OsvDispatchPreflightPolicy {
  const raw = record(input);
  const allowed = [
    "maxSchedules", "maximumObservations",
    "requireNoOpenCriticalIncidents", "requireNoUnsettledClaims",
    "requireNoUnsettledQuotas", "requireFreshInventory",
    "inspectSignatureAuthentication", "minimumRemainingRequests",
    "minimumRemainingInspections",
  ];
  if (Object.keys(raw).some(key => !allowed.includes(key)))
    bad("Unexpected dispatch preflight policy field.");
  return {
    maxSchedules: integer(raw.maxSchedules ?? 25,
      "schedule limit", 1, 50),
    maximumObservations: integer(raw.maximumObservations ?? 1000,
      "observation limit", 10, 10000),
    requireNoOpenCriticalIncidents:
      boolean(raw, "requireNoOpenCriticalIncidents", true),
    requireNoUnsettledClaims:
      boolean(raw, "requireNoUnsettledClaims", true),
    requireNoUnsettledQuotas:
      boolean(raw, "requireNoUnsettledQuotas", true),
    requireFreshInventory:
      boolean(raw, "requireFreshInventory", true),
    inspectSignatureAuthentication:
      boolean(raw, "inspectSignatureAuthentication", true),
    minimumRemainingRequests: integer(raw.minimumRemainingRequests ?? 1,
      "minimum request quota", 0, 200),
    minimumRemainingInspections: integer(raw.minimumRemainingInspections ?? 1,
      "minimum inspection quota", 0, 20),
  };
}
export function parsePreflightInput(input: unknown = {}):
  OsvDispatchPreflightInput {
  const raw = record(input);
  if (Object.keys(raw).some(key =>
    !["scheduleId", "policy"].includes(key)))
    bad("Unexpected dispatch preflight request property.");
  const id = raw.scheduleId ?? null;
  if (id !== null && (typeof id !== "string" ||
      !/^[A-Za-z0-9_-]{8,150}$/.test(id)))
    bad("Invalid requested schedule ID.");
  return {
    scheduleId: id,
    policy: parsePreflightPolicy(raw.policy ?? {}),
  };
}
function check(id: string, category: OsvDispatchPreflightCheck["category"],
  ok: boolean, summary: string, evidence:
    OsvDispatchPreflightCheck["evidence"],
  required = true): OsvDispatchPreflightCheck {
  return {
    id, category, level: ok ? "PASS" : required ? "BLOCK" : "WARN",
    summary, evidence, required,
  };
}
export type PreflightScheduleSnapshot = {
  id: string; name: string; revision: number; enabled: boolean;
  outboundConsent: boolean; consentedAt: Date | null;
  consentDigest: string; inventoryImportId: string;
  sourceInspectionId: string; nextDueAt: Date; cadenceMinutes: number;
  inspection: unknown; policy: unknown;
  allowNewPackages: boolean; allowIncompleteInventory: boolean;
};
export type PreflightEnvironmentSnapshot = {
  activeInventoryIds: Set<string>;
  sourceInspectionIds: Set<string>;
  openClaims: number; openQuotaReservations: number;
  openCriticalIncidents: number;
  remainingRequests: number; remainingInspections: number;
  keyConfig: DispatchKeyConfig;
};
export function evaluatePreflightSchedule(
  organizationId: string,
  schedule: PreflightScheduleSnapshot,
  environment: PreflightEnvironmentSnapshot,
  policy: OsvDispatchPreflightPolicy, now: Date,
): OsvDispatchPreflightSchedule {
  if (!Number.isFinite(now.getTime()))
    bad("Invalid dispatch preflight evaluation clock.");
  const checks: OsvDispatchPreflightCheck[] = [];
  const add = (id: string,
    category: OsvDispatchPreflightCheck["category"],
    ok: boolean, summary: string, evidence:
      OsvDispatchPreflightCheck["evidence"], required = true) =>
    checks.push(check(id, category, ok, summary, evidence, required));
  add("SCHEDULE_ENABLED", "CONSENT", schedule.enabled,
    "The schedule must be enabled explicitly.", schedule.enabled);
  add("OUTBOUND_CONSENT", "CONSENT", schedule.outboundConsent &&
    schedule.consentedAt !== null,
    "Explicit current outbound consent is required.",
    schedule.outboundConsent);
  let consentIntegrity = false;
  try {
    const config = parseOsvScheduleConfig({
      name: schedule.name,
      inventoryImportId: schedule.inventoryImportId,
      sourceInspectionId: schedule.sourceInspectionId,
      cadenceMinutes: schedule.cadenceMinutes,
      inspection: schedule.inspection, policy: schedule.policy,
      allowNewPackages: schedule.allowNewPackages,
      allowIncompleteInventory: schedule.allowIncompleteInventory,
    });
    consentIntegrity = scheduleConsentDigest(
      organizationId, config) === schedule.consentDigest;
  } catch { consentIntegrity = false; }
  add("CONSENT_DIGEST", "INTEGRITY", consentIntegrity,
    "The complete, canonical consent-bearing schedule must match the stored fingerprint.",
    consentIntegrity);
  add("ACTIVE_INVENTORY", "INVENTORY",
    environment.activeInventoryIds.has(schedule.inventoryImportId),
    "Only the original committed inventory may be renewed.",
    environment.activeInventoryIds.has(schedule.inventoryImportId),
    policy.requireFreshInventory);
  add("SOURCE_INSPECTION", "INVENTORY",
    environment.sourceInspectionIds.has(schedule.sourceInspectionId),
    "The previously accepted OSV inspection must still exist in this tenant.",
    environment.sourceInspectionIds.has(schedule.sourceInspectionId));
  const due = schedule.nextDueAt.getTime() <= now.getTime();
  add("SCHEDULE_DUE", "DUE", due,
    "The scheduled UTC slot must already be due.",
    schedule.nextDueAt.toISOString());
  const lag = now.getTime() - schedule.nextDueAt.getTime();
  const notTooOld = lag >= 0 && lag <= 30 * 86400000;
  add("DUE_WINDOW", "DUE", notTooOld,
    "Expired slots older than thirty days cannot be claimed.",
    Math.floor(lag / 60000));
  let nextDueAt: string;
  try {
    nextDueAt = nextOsvDueAt(
      schedule.nextDueAt, schedule.cadenceMinutes, now).toISOString();
  } catch { nextDueAt = schedule.nextDueAt.toISOString(); }
  add("NO_OPEN_CLAIMS", "CLAIMS",
    environment.openClaims === 0,
    "Outstanding claims require investigation before independent service dispatch.",
    environment.openClaims, policy.requireNoUnsettledClaims);
  add("NO_OPEN_QUOTA", "QUOTA",
    environment.openQuotaReservations === 0,
    "Unsettled provider reservations require investigation.",
    environment.openQuotaReservations, policy.requireNoUnsettledQuotas);
  add("NO_CRITICAL_INCIDENTS", "INCIDENTS",
    environment.openCriticalIncidents === 0,
    "Open critical operational incidents must be investigated.",
    environment.openCriticalIncidents,
    policy.requireNoOpenCriticalIncidents);
  add("REQUEST_QUOTA", "QUOTA",
    environment.remainingRequests >= policy.minimumRemainingRequests,
    "The daily request budget must meet the minimum operator threshold.",
    environment.remainingRequests);
  add("INSPECTION_QUOTA", "QUOTA",
    environment.remainingInspections >= policy.minimumRemainingInspections,
    "The daily inspection budget must meet the minimum operator threshold.",
    environment.remainingInspections);
  const config = inspectDispatchConfiguration(
    environment.keyConfig, organizationId);
  add("DISPATCH_ENABLED", "IDENTITY", config.enabled,
    "The internal signed dispatcher is currently enabled.", config.enabled);
  add("SCOPED_KEY", "IDENTITY", config.hasTenantKey,
    "At least one currently eligible tenant-scoped credential is required.",
    config.eligibleKeyIds.length);
  const result = {
    scheduleId: schedule.id, scheduleName: schedule.name,
    revision: schedule.revision, enabled: schedule.enabled,
    consented: schedule.outboundConsent && schedule.consentedAt !== null,
    inventoryImportId: schedule.inventoryImportId,
    dueAt: schedule.nextDueAt.toISOString(), nextDueAt,
    authorizingKeyIds: config.eligibleKeyIds,
    checks, blocked: checks.filter(row => row.level === "BLOCK").length,
    warnings: checks.filter(row => row.level === "WARN").length,
    passed: checks.filter(row => row.level === "PASS").length,
  };
  return {
    ...result, canConsiderManualDispatch: result.blocked === 0,
  };
}
export function simulateSignedDispatchChallenge(
  organizationId: string,
  scheduleId: string,
  revision: number,
  keys: DispatchKeyConfig,
  now: Date, keyId?: string,
): OsvDispatchChallenge {
  if (!Number.isFinite(now.getTime()))
    bad("Invalid signed dispatch test time.");
  const key = keys.keys.find(row =>
    row.organizationId === organizationId &&
    (keyId === undefined || row.id === keyId));
  const result: OsvDispatchChallenge = {
    schema: "cyberpilot.assets.osv.dispatch.challenge.v1",
    organizationId, scheduleId, scheduleRevision: revision,
    keyId: key?.id ?? "NO_TENANT_KEY",
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60000).toISOString(),
    protocolMatched: false,
    crossTenantRejected: false,
    signatureMutationRejected: false,
    expiredRejected: false,
    replayStoragePresent: true,
    authenticationAccepted: false,
    signedRequestSent: false, noncePersisted: false,
    providerContacted: false, scheduleChanged: false,
    warnings: [
      "Challenge is an in-process cryptographic test only; no nonce is committed.",
      "An accepted signature is not evidence that a schedule is currently due or provider quota is available.",
    ],
  };
  if (!key || !keys.enabled) return {
    ...result, warnings: [
      ...result.warnings,
      "No enabled, scoped key is available for this challenge.",
    ],
  };
  const nonce = randomUUID().replaceAll("-", "") +
    randomUUID().replaceAll("-", "");
  const intent = parseSignedDispatchIntent({
    schema: "cyberpilot.assets.osv.signed-dispatch.v1",
    organizationId, organizationSlug: "synthetic-preflight",
    scheduleId, expectedRevision: revision,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60000).toISOString(),
    nonce, confirmDispatch: true,
  });
  const signature = signOsvDispatch(intent, key.secretHex);
  const accepted = (() => {
    try {
      verifySignedDispatch(intent, key.id, signature, keys, now);
      return true;
    } catch { return false; }
  })();
  const altered = parseSignedDispatchIntent({
    ...intent, scheduleId: "synthetic-other-schedule-12345",
  });
  const signatureMutationRejected = (() => {
    try {
      verifySignedDispatch(altered, key.id, signature, keys, now);
      return false;
    } catch { return true; }
  })();
  const foreign = parseSignedDispatchIntent({
    ...intent, organizationId: "synthetic-foreign-tenant-12345",
  });
  const crossTenantRejected = (() => {
    try {
      verifySignedDispatch(foreign, key.id, signature, keys, now);
      return false;
    } catch { return true; }
  })();
  const expiredRejected = (() => {
    try {
      verifySignedDispatch(intent, key.id, signature, keys,
        new Date(now.getTime() + 120000));
      return false;
    } catch { return true; }
  })();
  return {
    ...result,
    protocolMatched: accepted && signature.length === 64,
    crossTenantRejected, signatureMutationRejected,
    expiredRejected, authenticationAccepted: accepted,
  };
}
export async function inspectOsvDispatchPreflight(
  scope: AssetScope, input: unknown = {}, now = new Date(),
): Promise<OsvDispatchPreflightReport> {
  requireScope(scope);
  if (!Number.isFinite(now.getTime()))
    bad("Invalid preflight evaluation time.");
  const request = parsePreflightInput(input);
  const p = request.policy;
  const [totalSchedules, schedules, claims, quotas, incidents,
    dailyQuota] = await Promise.all([
    db.assetOsvRenewalSchedule.count({
      where: {
        organizationId: scope.organizationId,
        ...(request.scheduleId ? { id: request.scheduleId } : {}),
      },
    }),
    db.assetOsvRenewalSchedule.findMany({
      where: {
        organizationId: scope.organizationId,
        ...(request.scheduleId ? { id: request.scheduleId } : {}),
      },
      take: p.maxSchedules + 1,
      orderBy: [{ nextDueAt: "asc" }, { id: "asc" }],
    }),
    db.assetOsvRenewalRun.count({
      where: { organizationId: scope.organizationId,
        state: "CLAIMED" },
    }),
    db.assetOsvQuotaReservation.count({
      where: { organizationId: scope.organizationId,
        state: "RESERVED" },
    }),
    db.assetOsvDispatchAlert.count({
      where: {
        organizationId: scope.organizationId,
        state: "OPEN", severity: "CRITICAL",
      },
    }),
    db.assetOsvQuotaDay.findUnique({
      where: {
        organizationId_utcDay: {
          organizationId: scope.organizationId,
          utcDay: new Date(Date.UTC(
            now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())),
        },
      },
    }),
  ]);
  if (request.scheduleId && totalSchedules === 0)
    throw new WorkInputError("MISSING",
      "Signed dispatch schedule not found in this organization.");
  if (totalSchedules > p.maximumObservations)
    throw new WorkInputError("CONFLICT",
      "Schedule preflight data exceeds the bounded observation limit.");
  const selected = schedules.slice(0, p.maxSchedules);
  const [imports, inspections] = await Promise.all([
    db.assetInventoryImport.findMany({
      where: {
        organizationId: scope.organizationId,
        id: { in: selected.map(row => row.inventoryImportId) },
      },
      select: { id: true, state: true },
    }),
    db.assetOsvInspection.findMany({
      where: {
        organizationId: scope.organizationId,
        id: { in: selected.map(row => row.sourceInspectionId) },
      }, select: { id: true, status: true },
    }),
  ]);
  const activeInventoryIds = new Set(imports.filter(row =>
    row.state === "COMMITTED").map(row => row.id));
  const sourceInspectionIds = new Set(inspections.filter(row =>
    row.status === "COMPLETE").map(row => row.id));
  const keys = configuredDispatchKeys();
  const env: PreflightEnvironmentSnapshot = {
    activeInventoryIds, sourceInspectionIds,
    openClaims: claims,
    openQuotaReservations: quotas,
    openCriticalIncidents: incidents,
    remainingRequests: dailyQuota ?
      Math.max(0, dailyQuota.requestLimit -
        dailyQuota.requestsReserved) : 200,
    remainingInspections: dailyQuota ?
      Math.max(0, dailyQuota.inspectionLimit -
        dailyQuota.inspectionsReserved) : 20,
    keyConfig: keys,
  };
  const evaluated = selected.map(row => evaluatePreflightSchedule(
    scope.organizationId, row, env, p, now));
  const common = {
    schema, organizationId: scope.organizationId,
    evaluatedAt: now.toISOString(),
    policy: p, selectedScheduleId: request.scheduleId,
    totalSchedules, scannedSchedules: evaluated.length,
    truncated: totalSchedules > selected.length,
    blockedSchedules: evaluated.filter(row =>
      row.blocked > 0).length,
    manuallyReviewableSchedules: evaluated.filter(row =>
      row.canConsiderManualDispatch).length,
    remainingRequests: env.remainingRequests,
    remainingInspections: env.remainingInspections,
    quotaReservationsOpen: quotas,
    claimsOpen: claims,
    criticalIncidentsOpen: incidents,
    keysEnabled: keys.enabled,
    previewOnly: true as const, outboundRequests: 0 as const,
    noncesConsumed: 0 as const, cronInstalled: false as const,
    schedules: evaluated,
  };
  return {
    ...common, digest: digest(common),
    warnings: [
      "Readiness is a point-in-time read-only preview and does not reserve quotas or claim slots.",
      "The signed dispatcher is disabled unless an operator explicitly configures tenant keys and the feature gate.",
      "This report is not LIVE acceptance of OSV.dev and cannot establish device security.",
      "Each real dispatch rechecks consent, revision, due time, source freshness, quota and unique slot atomically.",
      ...(totalSchedules > selected.length ?
        ["Schedule preview was truncated; do not infer readiness for unexamined schedules."] : []),
    ],
  };
}
