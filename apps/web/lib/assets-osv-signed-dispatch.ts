import {
  createHash, createHmac, timingSafeEqual,
} from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError } from "./remediation-work-input";
import { executeDueOsvSchedule } from "./assets-osv-renewal-schedules";
import type { OsvScheduledRunResult } from "./assets-osv-renewal-schedules";

/**
 * This module is intentionally fail-closed unless an operator installs a
 * separate scoped key and explicitly enables the dispatch HTTP boundary.
 * A signed request can claim only one pre-consented tenant schedule slot;
 * it cannot create schedules, change consent or bypass quota.
 */
export type SignedDispatchIntent = {
  schema: "cyberpilot.assets.osv.signed-dispatch.v1";
  organizationId: string;
  organizationSlug: string;
  scheduleId: string;
  expectedRevision: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  confirmDispatch: true;
};
export type DispatchKey = {
  id: string;
  organizationId: string;
  secretHex: string;
};
export type DispatchKeyConfig = {
  enabled: boolean;
  keys: DispatchKey[];
};
export type VerifiedDispatch = {
  organizationId: string;
  organizationSlug: string;
  scheduleId: string;
  expectedRevision: number;
  keyId: string;
  requestDigest: string;
  nonceDigest: string;
  issuedAt: Date;
  expiresAt: Date;
  intent: SignedDispatchIntent;
};
export type DispatchReceipt = {
  schema: "cyberpilot.assets.osv.signed-dispatch.receipt.v1";
  organizationId: string;
  scheduleId: string;
  requestDigest: string;
  nonceDigest: string;
  acceptedAt: string;
  keyId: string;
  result: OsvScheduledRunResult;
  warnings: string[];
};
export type DispatchReadiness = {
  schema: "cyberpilot.assets.osv.signed-dispatch.readiness.v1";
  enabled: boolean;
  scopedKeys: number;
  organizationId: string;
  eligibleKeyIds: string[];
  hasTenantKey: boolean;
  replayStorage: "POSTGRESQL";
  maxRequestAgeSeconds: 120;
  maxClockSkewSeconds: 30;
  grantsScheduleCreation: false;
  grantsConsentModification: false;
  grantsQuotaOverride: false;
  installsCron: false;
  warnings: string[];
};
const MAX_AGE = 120000;
const SKEW = 30000;
const SCHEMA = "cyberpilot.assets.osv.signed-dispatch.v1" as const;
const receiptSchema = "cyberpilot.assets.osv.signed-dispatch.receipt.v1" as const;
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function denied(message: string): never {
  throw new WorkInputError("FORBIDDEN", message);
}
function conflict(message: string): never {
  throw new WorkInputError("CONFLICT", message);
}
function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value);
}
function only(value: Record<string, unknown>, fields: string[]) {
  if (Object.keys(value).some(key => !fields.includes(key)))
    invalid("Unexpected signed dispatcher field.");
}
function text(value: unknown, label: string, max: number,
  pattern: RegExp): string {
  if (typeof value !== "string" || value.length > max ||
      !pattern.test(value))
    invalid("Invalid signed dispatcher " + label + ".");
  return value;
}
function time(value: unknown, label: string): Date {
  const raw = text(value, label, 30,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime()) ||
      parsed.toISOString() !== raw)
    invalid("Invalid signed dispatcher " + label + ".");
  return parsed;
}
function hash(value: string) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
function hex(value: unknown, label: string, length: number): string {
  return text(value, label, length,
    new RegExp("^[a-f0-9]{" + length + "}$"));
}
export function parseSignedDispatchIntent(input: unknown): SignedDispatchIntent {
  if (!isObject(input))
    invalid("Expected signed dispatch JSON object.");
  only(input, [
    "schema", "organizationId", "organizationSlug",
    "scheduleId", "expectedRevision", "issuedAt", "expiresAt",
    "nonce", "confirmDispatch",
  ]);
  if (input.schema !== SCHEMA)
    invalid("Unsupported dispatcher protocol version.");
  const organizationId = text(input.organizationId, "organization ID",
    150, /^[A-Za-z0-9_-]{8,150}$/);
  const organizationSlug = text(input.organizationSlug, "organization slug",
    150, /^[a-z0-9][a-z0-9_-]{2,149}$/);
  const scheduleId = text(input.scheduleId, "schedule ID",
    150, /^[A-Za-z0-9_-]{8,150}$/);
  if (typeof input.expectedRevision !== "number" ||
      !Number.isSafeInteger(input.expectedRevision) ||
      input.expectedRevision < 1 || input.expectedRevision > 10000000)
    invalid("Expected a positive schedule revision.");
  if (input.confirmDispatch !== true)
    invalid("Signed dispatch must explicitly confirm the due slot.");
  const issuedAt = time(input.issuedAt, "issuedAt");
  const expiresAt = time(input.expiresAt, "expiresAt");
  if (expiresAt.getTime() <= issuedAt.getTime() ||
      expiresAt.getTime() - issuedAt.getTime() > MAX_AGE)
    invalid("Signed dispatch validity exceeds maximum window.");
  const nonce = text(input.nonce, "nonce",
    128, /^[a-zA-Z0-9_-]{24,128}$/);
  return {
    schema: SCHEMA, organizationId, organizationSlug, scheduleId,
    expectedRevision: input.expectedRevision,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(), nonce, confirmDispatch: true,
  };
}
export function parseDispatchKeyConfig(
  enabledValue: unknown, rawValue: unknown,
): DispatchKeyConfig {
  if (enabledValue !== undefined && enabledValue !== "true" &&
      enabledValue !== "false")
    invalid("Signed OSV dispatch toggle must be explicitly true or false.");
  const enabled = enabledValue === "true";
  if (!enabled) return { enabled: false, keys: [] };
  if (typeof rawValue !== "string" || rawValue.length > 16384)
    denied("No scoped dispatch credential configuration is available.");
  let data: unknown;
  try { data = JSON.parse(rawValue); }
  catch { denied("Invalid dispatcher key configuration."); }
  if (!Array.isArray(data) || data.length < 1 || data.length > 30)
    denied("Expected a bounded nonempty dispatcher key set.");
  const keys: DispatchKey[] = [];
  const seen = new Set<string>();
  for (const row of data) {
    if (!isObject(row)) denied("Invalid scoped dispatcher key.");
    only(row, ["id", "organizationId", "secretHex"]);
    const id = text(row.id, "key ID", 100, /^[A-Za-z0-9_-]{8,100}$/);
    const organizationId = text(row.organizationId, "key organization",
      150, /^[A-Za-z0-9_-]{8,150}$/);
    const secretHex = hex(row.secretHex, "key material", 64);
    if (seen.has(id)) denied("Dispatcher key IDs must be unique.");
    seen.add(id);
    keys.push({ id, organizationId, secretHex });
  }
  return { enabled, keys };
}
export function configuredDispatchKeys(): DispatchKeyConfig {
  return parseDispatchKeyConfig(
    process.env.CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED,
    process.env.CYBERPILOT_OSV_DISPATCH_KEYS,
  );
}
export function signedDispatchCanonical(
  intent: SignedDispatchIntent,
): string {
  // Fixed field ordering and endpoint bind the signature to a single
  // HTTP action; never rely on client-controlled JSON serialization order.
  return [
    "cyberpilot.osv.signed-dispatch.v1",
    "POST",
    "/api/internal/osv/signed-dispatch",
    intent.organizationId,
    intent.organizationSlug,
    intent.scheduleId,
    String(intent.expectedRevision),
    intent.issuedAt,
    intent.expiresAt,
    intent.nonce,
    intent.confirmDispatch ? "true" : "false",
  ].join("\n");
}
export function signOsvDispatch(
  intent: SignedDispatchIntent, secretHex: string,
): string {
  hex(secretHex, "key material", 64);
  return createHmac("sha256", Buffer.from(secretHex, "hex"))
    .update(signedDispatchCanonical(intent), "utf8").digest("hex");
}
export function verifyDispatchSignature(
  intent: SignedDispatchIntent,
  key: DispatchKey, signatureValue: unknown,
): boolean {
  if (key.organizationId !== intent.organizationId) return false;
  if (typeof signatureValue !== "string" ||
      !/^[a-f0-9]{64}$/.test(signatureValue)) return false;
  const expected = signOsvDispatch(intent, key.secretHex);
  return timingSafeEqual(
    Buffer.from(expected, "hex"), Buffer.from(signatureValue, "hex"));
}
export function validateSignedDispatchTime(
  intent: SignedDispatchIntent, now: Date,
): void {
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid dispatch evaluation timestamp.");
  const issued = new Date(intent.issuedAt).getTime();
  const expires = new Date(intent.expiresAt).getTime();
  if (issued > now.getTime() + SKEW ||
      now.getTime() > expires ||
      now.getTime() - issued > MAX_AGE + SKEW)
    denied("Signed dispatch is expired or outside clock tolerance.");
}
export function verifySignedDispatch(
  raw: unknown, keyId: unknown, signature: unknown,
  config: DispatchKeyConfig, now = new Date(),
): VerifiedDispatch {
  if (!config.enabled)
    denied("Signed OSV service dispatch is not enabled.");
  const intent = parseSignedDispatchIntent(raw);
  validateSignedDispatchTime(intent, now);
  if (typeof keyId !== "string" || keyId.length > 100)
    denied("Missing dispatch key identity.");
  const key = config.keys.find(row => row.id === keyId);
  if (!key || !verifyDispatchSignature(intent, key, signature))
    denied("Signed OSV dispatch authentication failed.");
  const canonical = signedDispatchCanonical(intent);
  return {
    organizationId: intent.organizationId,
    organizationSlug: intent.organizationSlug,
    scheduleId: intent.scheduleId,
    expectedRevision: intent.expectedRevision,
    keyId: key.id, issuedAt: new Date(intent.issuedAt),
    expiresAt: new Date(intent.expiresAt),
    requestDigest: hash(canonical),
    nonceDigest: hash(intent.organizationId + "\n" + intent.nonce),
    intent,
  };
}
export function inspectDispatchConfiguration(
  config: DispatchKeyConfig, organizationId: string,
): DispatchReadiness {
  const eligible = config.enabled ?
    config.keys.filter(key => key.organizationId === organizationId)
      .map(key => key.id).sort() : [];
  return {
    schema: "cyberpilot.assets.osv.signed-dispatch.readiness.v1",
    enabled: config.enabled,
    scopedKeys: config.keys.length,
    organizationId, eligibleKeyIds: eligible,
    hasTenantKey: eligible.length > 0,
    replayStorage: "POSTGRESQL",
    maxRequestAgeSeconds: 120, maxClockSkewSeconds: 30,
    grantsScheduleCreation: false, grantsConsentModification: false,
    grantsQuotaOverride: false, installsCron: false,
    warnings: [
      "A scoped service key must be installed and explicitly enabled by an operator.",
      "The signed dispatch endpoint does not create schedules, grant consent or override quotas.",
      "Each nonce is durably consumed before schedule execution; failures remain spent.",
      "No recurring timer or external tenant connector is provisioned by this module.",
    ],
  };
}
export async function consumeSignedDispatch(
  verified: VerifiedDispatch, now = new Date(),
): Promise<void> {
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid replay prevention timestamp.");
  // Never expose signed authentication errors before checking the tenant.
  const organization = await db.organization.findFirst({
    where: {
      id: verified.organizationId,
      slug: verified.organizationSlug,
    }, select: { id: true },
  });
  if (!organization)
    denied("Signed dispatcher organization scope is invalid.");
  const schedule = await db.assetOsvRenewalSchedule.findFirst({
    where: {
      id: verified.scheduleId,
      organizationId: verified.organizationId,
      enabled: true, outboundConsent: true,
      revision: verified.expectedRevision,
      nextDueAt: { lte: now },
    },
    select: { id: true, nextDueAt: true, createdByUserId: true },
  });
  if (!schedule)
    conflict("The authorized schedule is not currently claimable.");
  try {
    await db.assetOsvDispatchNonce.create({
      data: {
        organizationId: verified.organizationId,
        nonceDigest: verified.nonceDigest,
        requestDigest: verified.requestDigest,
        keyId: verified.keyId,
        scheduleId: verified.scheduleId,
        expiresAt: verified.expiresAt,
      },
    });
  } catch (cause) {
    if (cause && typeof cause === "object" &&
        "code" in cause && cause.code === "P2002")
      conflict("Signed dispatch nonce has already been consumed.");
    throw cause;
  }
}
export async function executeSignedOsvDispatch(
  verified: VerifiedDispatch, now = new Date(),
): Promise<DispatchReceipt> {
  await consumeSignedDispatch(verified, now);
  // This is a tenant-scoped SERVICE dispatch. The scheduler remains guarded
  // by consent, revision CAS, unique slot, retry cooldown and atomic quotas.
  // The service's actor ID is a sentinel, never a real user identity.
  const result = await executeDueOsvSchedule({
    organizationId: verified.organizationId,
    userId: "osv-signed-dispatch-service",
    role: "ADMIN",
  }, {
    scheduleId: verified.scheduleId,
    expectedRevision: verified.expectedRevision,
    confirmDispatch: true,
  }, { now: () => now, actorType: "SERVICE" });
  return {
    schema: receiptSchema,
    organizationId: verified.organizationId,
    scheduleId: verified.scheduleId,
    requestDigest: verified.requestDigest,
    nonceDigest: verified.nonceDigest,
    acceptedAt: now.toISOString(), keyId: verified.keyId,
    result,
    warnings: [
      "Authentication only permits an already-consented due slot.",
      "A consumed nonce is not retried after provider or database failure.",
      "An UNKNOWN provider outcome does not release daily quota.",
      "No autonomous scheduler or external tenant has been enabled.",
    ],
  };
}
