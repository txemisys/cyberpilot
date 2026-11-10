import { createHash, randomBytes } from "node:crypto";
import { db } from "@cyberpilot/database";
import { WorkInputError, canManageWork } from "./remediation-work-input";
import {
  configuredDispatchKeys, dispatchKeyPermitsRequest,
  parseDispatchKeyConfig, parseSignedDispatchIntent,
} from "./assets-osv-signed-dispatch";
import type {
  DispatchKey, DispatchKeyConfig, SignedDispatchIntent,
} from "./assets-osv-signed-dispatch";
import type { AssetScope } from "./assets-inventory-service";

/**
 * A zero-secret, read-only HMAC key rotation advisory. The app never writes
 * signing secrets into PostgreSQL and does not modify deployment variables.
 * Config changes are performed independently via secret-management tooling.
 */
export type KeyRotationState = "ACTIVE" | "RETIRING" | "REVOKED";
export type KeyRotationPolicy = {
  maximumActiveKeys: number;
  minimumOverlapMinutes: number;
  maximumOverlapMinutes: number;
  warningLeadHours: number;
  requireDistinctMaterial: boolean;
  requireZeroOutstandingClaims: boolean;
};
export type KeyRotationInput = {
  organizationId: string;
  retiringKeyId: string;
  replacingKeyId: string;
  effectiveAt: string;
  retireAt: string;
  notBefore: string;
  notAfter: string;
  policy: KeyRotationPolicy;
};
export type KeyRotationKeyStatus = {
  id: string;
  organizationId: string;
  state: KeyRotationState;
  notBefore: string | null;
  notAfter: string | null;
  currentlyAccepting: boolean;
  acceptsAtActivation: boolean;
  acceptsAtRetirement: boolean;
  expiresSoon: boolean;
  validInterval: boolean;
  weakSchedule: boolean;
  observations: string[];
};
export type KeyRotationPlan = {
  schema: "cyberpilot.assets.osv.rotation.plan.v1";
  organizationId: string;
  generatedAt: string;
  retiringKeyId: string;
  replacingKeyId: string;
  effectiveAt: string;
  retireAt: string;
  keyCount: number;
  keysForTenant: KeyRotationKeyStatus[];
  activeAtEffective: number;
  activeAtRetirement: number;
  overlappingMinutes: number;
  outstandingClaims: number;
  unsettledQuotas: number;
  recentAcceptedNonces: number;
  readyForOperatorReview: boolean;
  warnings: string[];
  blockingReasons: string[];
  previewDigest: string;
  secretsExposed: false;
  changesApplied: false;
};
export type KeyRotationInventory = {
  schema: "cyberpilot.assets.osv.rotation.inventory.v1";
  organizationId: string;
  examinedAt: string;
  configured: boolean;
  keyCount: number;
  activeKeyCount: number;
  retiringKeyCount: number;
  revokedKeyCount: number;
  keys: KeyRotationKeyStatus[];
  warnings: string[];
  secretsExposed: false;
};
export type KeyRotationDryRun = {
  schema: "cyberpilot.assets.osv.rotation.dry-run.v1";
  organizationId: string;
  evaluatedAt: string;
  before: KeyRotationInventory;
  after: KeyRotationInventory;
  plan: KeyRotationPlan;
  proposedConfigurationDigest: string;
  noSecretsOrConfigWritten: true;
  rolloutStages: Array<{
    stage: "PREPARE" | "VERIFY" | "OVERLAP" | "RETIRE" | "REVOKE";
    requiresHumanApproval: true;
    instruction: string;
    rollbackConsideration: string;
  }>;
};
const MAX_INTERVAL_MS = 365 * 86400000;
function invalid(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function forbidden(message: string): never {
  throw new WorkInputError("FORBIDDEN", message);
}
function conflicting(message: string): never {
  throw new WorkInputError("CONFLICT", message);
}
function record(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    invalid("Key rotation request must be an object.");
  return input as Record<string, unknown>;
}
function fields(raw: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(raw).some(k => !allowed.includes(k)))
    invalid("Unexpected key rotation property.");
}
function string(input: unknown, label: string,
  max: number, pattern: RegExp): string {
  if (typeof input !== "string" || input.length > max ||
      !pattern.test(input))
    invalid("Invalid key rotation " + label + ".");
  return input;
}
function number(input: unknown, label: string,
  min: number, max: number) {
  if (typeof input !== "number" || !Number.isSafeInteger(input) ||
      input < min || input > max)
    invalid("Invalid key rotation " + label + ".");
  return input;
}
function timestamp(input: unknown, label: string) {
  const value = string(input, label, 30,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) ||
      date.toISOString() !== value)
    invalid("Invalid key rotation timestamp: " + label + ".");
  return date;
}
function hash(input: unknown) {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
function human(key: DispatchKey): Omit<DispatchKey, "secretHex"> {
  return {
    id: key.id, organizationId: key.organizationId,
    ...(key.state ? { state: key.state } : {}),
    ...(key.notBefore ? { notBefore: key.notBefore } : {}),
    ...(key.notAfter ? { notAfter: key.notAfter } : {}),
  };
}
export function parseKeyRotationPolicy(
  input: unknown = {},
): KeyRotationPolicy {
  const raw = record(input);
  fields(raw, [
    "maximumActiveKeys", "minimumOverlapMinutes",
    "maximumOverlapMinutes", "warningLeadHours",
    "requireDistinctMaterial", "requireZeroOutstandingClaims",
  ]);
  for (const key of ["requireDistinctMaterial", "requireZeroOutstandingClaims"])
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      invalid("Invalid rotation boolean: " + key);
  const policy = {
    maximumActiveKeys: number(raw.maximumActiveKeys ?? 2,
      "maximum active keys", 1, 10),
    minimumOverlapMinutes: number(raw.minimumOverlapMinutes ?? 15,
      "minimum overlap", 1, 43200),
    maximumOverlapMinutes: number(raw.maximumOverlapMinutes ?? 1440,
      "maximum overlap", 1, 43200),
    warningLeadHours: number(raw.warningLeadHours ?? 72,
      "warning lead", 1, 720),
    requireDistinctMaterial: raw.requireDistinctMaterial !== false,
    requireZeroOutstandingClaims: raw.requireZeroOutstandingClaims !== false,
  };
  if (policy.minimumOverlapMinutes > policy.maximumOverlapMinutes)
    invalid("Minimum overlap cannot exceed maximum overlap.");
  return policy;
}
export function parseKeyRotationInput(input: unknown): KeyRotationInput {
  const raw = record(input);
  fields(raw, [
    "organizationId", "retiringKeyId", "replacingKeyId",
    "effectiveAt", "retireAt", "notBefore", "notAfter", "policy",
  ]);
  const organizationId = string(raw.organizationId,
    "organization", 150, /^[A-Za-z0-9_-]{8,150}$/);
  const retiringKeyId = string(raw.retiringKeyId,
    "retiring key", 100, /^[A-Za-z0-9_-]{8,100}$/);
  const replacingKeyId = string(raw.replacingKeyId,
    "replacement key", 100, /^[A-Za-z0-9_-]{8,100}$/);
  if (retiringKeyId === replacingKeyId)
    invalid("Rotating keys requires distinct credential IDs.");
  const effective = timestamp(raw.effectiveAt, "activation");
  const retirement = timestamp(raw.retireAt, "retirement");
  const notBefore = timestamp(raw.notBefore, "replacement notBefore");
  const notAfter = timestamp(raw.notAfter, "replacement notAfter");
  if (retirement <= effective)
    invalid("Retirement must follow activation.");
  if (notAfter <= notBefore ||
      notAfter.getTime() - notBefore.getTime() > MAX_INTERVAL_MS)
    invalid("Replacement key lifetime is invalid or exceeds one year.");
  if (notBefore > effective || notAfter <= retirement)
    invalid("Replacement must cover the full proposed cutover.");
  const policy = parseKeyRotationPolicy(raw.policy ?? {});
  return {
    organizationId, retiringKeyId, replacingKeyId,
    effectiveAt: effective.toISOString(),
    retireAt: retirement.toISOString(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    policy,
  };
}
function syntheticIntent(org: string, instant: Date): SignedDispatchIntent {
  const start = instant.toISOString();
  return parseSignedDispatchIntent({
    schema: "cyberpilot.assets.osv.signed-dispatch.v1",
    organizationId: org, organizationSlug: "synthetic-check",
    scheduleId: "synthetic-check-schedule",
    expectedRevision: 1, issuedAt: start,
    expiresAt: new Date(instant.getTime() + 60000).toISOString(),
    nonce: "synthetic-only-not-a-real-dispatch",
    confirmDispatch: true,
  });
}
export function inspectRotationKey(
  key: DispatchKey, now: Date,
  policy: KeyRotationPolicy,
  organizationId = key.organizationId,
  effectiveAt = now,
  retireAt = new Date(now.getTime() + 86400000),
): KeyRotationKeyStatus {
  const state = key.state ?? "ACTIVE";
  const notBefore = key.notBefore ?
    new Date(key.notBefore).getTime() : -Infinity;
  const notAfter = key.notAfter ?
    new Date(key.notAfter).getTime() : Infinity;
  const validInterval = notBefore < notAfter &&
    !Number.isNaN(notBefore) && !Number.isNaN(notAfter);
  const accepting = (time: Date) =>
    key.organizationId === organizationId && validInterval &&
    dispatchKeyPermitsRequest(
      key, syntheticIntent(organizationId, time), time);
  const expiresSoon = Number.isFinite(notAfter) &&
    notAfter > now.getTime() &&
    notAfter - now.getTime() <= policy.warningLeadHours * 3600000;
  const weakSchedule = state === "RETIRING" && !key.notAfter;
  const observations: string[] = [];
  if (!validInterval) observations.push("Invalid key activation interval.");
  if (state === "REVOKED")
    observations.push("Revoked key never accepts newly signed dispatches.");
  if (weakSchedule)
    observations.push("Retiring key has no expiry and is rejected.");
  if (expiresSoon)
    observations.push("Key expiry is approaching its configured threshold.");
  if (key.organizationId !== organizationId)
    observations.push("Key belongs to a different organization.");
  return {
    id: key.id, organizationId: key.organizationId, state,
    notBefore: key.notBefore ?? null,
    notAfter: key.notAfter ?? null,
    currentlyAccepting: accepting(now),
    acceptsAtActivation: accepting(effectiveAt),
    acceptsAtRetirement: accepting(retireAt),
    expiresSoon, validInterval, weakSchedule, observations,
  };
}
export function inspectRotationInventory(
  config: DispatchKeyConfig, orgId: string,
  now: Date, policy = parseKeyRotationPolicy({}),
): KeyRotationInventory {
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid rotation inventory evaluation time.");
  const keys = config.keys.filter(key => key.organizationId === orgId)
    .map(key => inspectRotationKey(key, now, policy))
    .sort((a, b) => a.id.localeCompare(b.id));
  return {
    schema: "cyberpilot.assets.osv.rotation.inventory.v1",
    organizationId: orgId,
    examinedAt: now.toISOString(), configured: config.enabled,
    keyCount: keys.length,
    activeKeyCount: keys.filter(key => key.currentlyAccepting).length,
    retiringKeyCount: keys.filter(key => key.state === "RETIRING").length,
    revokedKeyCount: keys.filter(key => key.state === "REVOKED").length,
    keys, secretsExposed: false,
    warnings: [
      "Only credential IDs, scoped organization and validity periods are returned.",
      "No raw key secret, HMAC signature or signing credential is persisted or displayed.",
      "The operator must apply rotation in the deployment secret manager.",
    ],
  };
}
export function evaluateRotationPlan(
  current: DispatchKeyConfig, input: KeyRotationInput,
  now: Date, outstandingClaims: number,
  unsettledQuotas: number, recentAcceptedNonces: number,
  proposedReplacement?: DispatchKey,
): KeyRotationPlan {
  if (!Number.isFinite(now.getTime()))
    invalid("Invalid rotation assessment timestamp.");
  if (!Number.isSafeInteger(outstandingClaims) || outstandingClaims < 0 ||
      !Number.isSafeInteger(unsettledQuotas) || unsettledQuotas < 0 ||
      !Number.isSafeInteger(recentAcceptedNonces) || recentAcceptedNonces < 0)
    invalid("Invalid rotation observation counters.");
  const keys = current.keys.filter(key =>
    key.organizationId === input.organizationId);
  const old = keys.find(key => key.id === input.retiringKeyId);
  const replacement = proposedReplacement ??
    keys.find(key => key.id === input.replacingKeyId);
  const observations: DispatchKey[] = keys.map(key =>
    key.id === input.retiringKeyId ? {
      ...key, state: "RETIRING",
      notAfter: input.retireAt,
    } : key.id === input.replacingKeyId ? {
      ...key, state: "ACTIVE",
      notBefore: input.notBefore, notAfter: input.notAfter,
    } : key);
  if (proposedReplacement && !keys.some(x =>
    x.id === input.replacingKeyId))
    observations.push({
      ...proposedReplacement, state: "ACTIVE",
      notBefore: input.notBefore, notAfter: input.notAfter,
    });
  const atActivation = new Date(input.effectiveAt);
  const atRetirement = new Date(input.retireAt);
  const policy = input.policy;
  const simulated = observations.map(key =>
    inspectRotationKey(key, now, policy, input.organizationId,
      atActivation, atRetirement));
  const activeAtEffective = simulated.filter(x =>
    x.acceptsAtActivation).length;
  const activeAtRetirement = simulated.filter(x =>
    x.acceptsAtRetirement).length;
  const overlap = (atRetirement.getTime() -
    atActivation.getTime()) / 60000;
  const reasons: string[] = [];
  if (!current.enabled)
    reasons.push("Dispatcher remains disabled; the rotation is planning-only.");
  if (!old)
    reasons.push("Retiring key is not present in this organization.");
  if (old?.state === "REVOKED")
    reasons.push("Retiring key is already revoked.");
  if (!replacement)
    reasons.push("Replacement key is not present in approved configuration.");
  if (replacement &&
      replacement.organizationId !== input.organizationId)
    reasons.push("Replacement key belongs to another organization.");
  if (old && replacement && policy.requireDistinctMaterial &&
      old.secretHex === replacement.secretHex)
    reasons.push("Replacement must have distinct cryptographic material.");
  if (atActivation.getTime() < now.getTime())
    reasons.push("Rotation activation is already in the past.");
  if (overlap < policy.minimumOverlapMinutes ||
      overlap > policy.maximumOverlapMinutes)
    reasons.push("Overlap duration violates operator policy.");
  if (activeAtEffective < 2)
    reasons.push("Both old and replacement keys must work at cutover.");
  if (activeAtEffective > policy.maximumActiveKeys)
    reasons.push("Too many simultaneously active keys at cutover.");
  if (activeAtRetirement < 1)
    reasons.push("No replacement key would be active after retirement.");
  if (simulated.find(x => x.id === input.retiringKeyId)
      ?.acceptsAtRetirement)
    reasons.push("Retiring key still accepts requests after cutover.");
  if (policy.requireZeroOutstandingClaims && outstandingClaims > 0)
    reasons.push("Unsettled claims must be investigated before rotating.");
  if (policy.requireZeroOutstandingClaims && unsettledQuotas > 0)
    reasons.push("Unsettled quota reservations must be investigated.");
  const canonical = {
    schema: "cyberpilot.assets.osv.rotation.plan.v1" as const,
    organizationId: input.organizationId,
    generatedAt: now.toISOString(),
    retiringKeyId: input.retiringKeyId,
    replacingKeyId: input.replacingKeyId,
    effectiveAt: input.effectiveAt, retireAt: input.retireAt,
    keyCount: keys.length,
    keysForTenant: simulated,
    activeAtEffective, activeAtRetirement,
    overlappingMinutes: overlap,
    outstandingClaims, unsettledQuotas, recentAcceptedNonces,
    readyForOperatorReview: reasons.length === 0,
    warnings: [
      "This preview neither activates a key nor changes deployment credentials.",
      "Accepted nonces remain spent across key rotation; never purge replay records for convenience.",
      "Revoked keys are rejected immediately; key expiration alone does not resolve active incidents.",
      "Never paste secret key material into the app UI or incident notes.",
    ],
    blockingReasons: reasons,
    secretsExposed: false as const,
    changesApplied: false as const,
  };
  return { ...canonical, previewDigest: hash({
    schema: canonical.schema,
    organizationId: canonical.organizationId,
    retiringKeyId: canonical.retiringKeyId,
    replacingKeyId: canonical.replacingKeyId,
    effectiveAt: canonical.effectiveAt,
    retireAt: canonical.retireAt,
    keys: observations.map(human).sort((a, b) =>
      a.id.localeCompare(b.id)),
    outstandingClaims, unsettledQuotas, recentAcceptedNonces,
    policy,
  }) };
}
export function proposeOsvKeyRotation(
  config: DispatchKeyConfig, input: KeyRotationInput,
  now: Date, outstandingClaims: number,
  unsettledQuotas: number, recentAcceptedNonces: number,
): KeyRotationDryRun {
  const existing = config.keys.find(key =>
    key.organizationId === input.organizationId &&
    key.id === input.replacingKeyId);
  const hypothetical = existing ? undefined : {
    id: input.replacingKeyId,
    organizationId: input.organizationId,
    // Synthetic material must never be returned or persisted.
    secretHex: "a5".repeat(32),
  };
  const plan = evaluateRotationPlan(config, input, now,
    outstandingClaims, unsettledQuotas,
    recentAcceptedNonces, hypothetical);
  if (!existing)
    plan.blockingReasons.push(
      "Replacement key is synthetic in the preview; provision it independently before activation.");
  plan.readyForOperatorReview = plan.blockingReasons.length === 0;
  const afterKeys = config.keys.map(key =>
    key.organizationId === input.organizationId &&
    key.id === input.retiringKeyId ?
      { ...key, state: "RETIRING" as const,
        notAfter: input.retireAt } :
      key.organizationId === input.organizationId &&
      key.id === input.replacingKeyId ?
        { ...key, state: "ACTIVE" as const,
          notBefore: input.notBefore, notAfter: input.notAfter } :
        key);
  if (hypothetical) afterKeys.push({
    ...hypothetical, state: "ACTIVE",
    notBefore: input.notBefore, notAfter: input.notAfter,
  });
  const after = inspectRotationInventory({
    enabled: config.enabled, keys: afterKeys,
  }, input.organizationId, now, input.policy);
  return {
    schema: "cyberpilot.assets.osv.rotation.dry-run.v1",
    organizationId: input.organizationId,
    evaluatedAt: now.toISOString(),
    before: inspectRotationInventory(
      config, input.organizationId, now, input.policy),
    after, plan,
    proposedConfigurationDigest: hash(
      afterKeys.filter(key => key.organizationId ===
        input.organizationId).map(human).sort((a, b) =>
          a.id.localeCompare(b.id))),
    noSecretsOrConfigWritten: true,
    rolloutStages: [
      {
        stage: "PREPARE", requiresHumanApproval: true,
        instruction: "Create a distinct 256-bit secret for the replacement key in the production secret manager.",
        rollbackConsideration: "Do not change or delete the existing key until deployment replicas agree.",
      }, {
        stage: "VERIFY", requiresHumanApproval: true,
        instruction: "Verify tenant ID, signature and time window with a test that cannot contact the provider.",
        rollbackConsideration: "Leave the service disabled if clock skew, replica synchronization or key scope is uncertain.",
      }, {
        stage: "OVERLAP", requiresHumanApproval: true,
        instruction: "Publish both keys with explicit activation and retirement timestamps, then inspect audit records.",
        rollbackConsideration: "Monitor both old and new key IDs without exposing either secret.",
      }, {
        stage: "RETIRE", requiresHumanApproval: true,
        instruction: "Set the previous key to RETIRING with its cutover expiry; stop generating signatures with it.",
        rollbackConsideration: "Investigate signed nonces, claimed slots and quota before changing windows.",
      }, {
        stage: "REVOKE", requiresHumanApproval: true,
        instruction: "Mark the old key REVOKED and remove its secret from deployment only after accepted cutover.",
        rollbackConsideration: "Do not reuse an old key ID or delete audit/nonces to simulate recovery.",
      },
    ],
  };
}
export async function inspectOsvRotationOperations(
  scope: AssetScope, input: unknown, now = new Date(),
): Promise<KeyRotationDryRun> {
  if (!canManageWork(scope.role))
    forbidden("Only tenant administrators can inspect dispatch key rotation.");
  const command = parseKeyRotationInput(input);
  if (scope.organizationId !== command.organizationId)
    forbidden("Key rotation request belongs to another organization.");
  const [outstandingClaims, unsettledQuotas, recentAcceptedNonces] =
    await Promise.all([
      db.assetOsvRenewalRun.count({
        where: { organizationId: scope.organizationId,
          state: "CLAIMED" },
      }),
      db.assetOsvQuotaReservation.count({
        where: { organizationId: scope.organizationId,
          state: "RESERVED" },
      }),
      db.assetOsvDispatchNonce.count({
        where: { organizationId: scope.organizationId,
          acceptedAt: { gte: new Date(now.getTime() - 86400000) } },
      }),
    ]);
  return proposeOsvKeyRotation(configuredDispatchKeys(),
    command, now, outstandingClaims, unsettledQuotas,
    recentAcceptedNonces);
}
export function createSyntheticRotationFixture() {
  // Pure test helper. Never use synthetic credentials in a real deployment.
  const now = new Date("2026-11-10T12:00:00.000Z");
  const keys: DispatchKey[] = [
    { id: "fixture-key-old-12345",
      organizationId: "fixture-organization-12345",
      secretHex: randomBytes(32).toString("hex") },
    { id: "fixture-key-new-12345",
      organizationId: "fixture-organization-12345",
      secretHex: randomBytes(32).toString("hex") },
  ];
  return { now, keys };
}
