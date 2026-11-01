import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest, type SnapshotManifest } from "./work-integrity-snapshot-integrity";

/**
 * Portable authenticated snapshot bundles.
 *
 * This module is intentionally separate from the unsigned diagnostic APIs.
 * Key material must be provisioned by the caller from a trusted secret store.
 * Authentication is scoped to an organization and a key identifier; a shared
 * secret is not proof of the individual operator's identity.
 */
export type BundlePolicy = {
  maximumCaptures: number;
  maximumBytes: number;
  maximumAgeSeconds: number;
  allowedClockSkewSeconds: number;
  requireCompleteCaptures: boolean;
  allowedSources: readonly string[] | null;
};
export type BundleSignature = {
  algorithm: "HMAC-SHA256";
  keyId: string;
  digest: string;
};
export type AuthenticatedBundle = {
  format: "cyberpilot-snapshot-bundle";
  version: 1;
  organizationId: string;
  createdAt: string;
  expiresAt: string;
  nonce: string;
  captures: CaseSnapshot[];
  manifest: SnapshotManifest;
  signature: BundleSignature;
};
export type BundleValidationCode =
  | "VERIFIED" | "MALFORMED" | "WRONG_ORGANIZATION" | "WRONG_KEY"
  | "INVALID_SIGNATURE" | "EXPIRED" | "FUTURE" | "MANIFEST_CHANGED"
  | "CAPTURE_POLICY" | "REPLAYED" | "UNTRUSTED_KEY";
export type BundleValidation = {
  verified: boolean;
  code: BundleValidationCode;
  organizationId: string;
  keyId: string | null;
  manifestRoot: string | null;
  captureCount: number;
  createdAt: string | null;
  expiresAt: string | null;
  warnings: string[];
};
export type BundleKey = {
  id: string;
  secret: Uint8Array;
  activeFrom: string;
  activeUntil: string | null;
  revoked: boolean;
};
export type BundleKeyring = {
  getKey(organizationId: string, keyId: string): BundleKey | null;
};
export type BundleReplayLedger = {
  hasSeen(organizationId: string, keyId: string, nonce: string): boolean;
};
export const DEFAULT_BUNDLE_POLICY: BundlePolicy = {
  maximumCaptures: 1000,
  maximumBytes: 5_000_000,
  maximumAgeSeconds: 86400,
  allowedClockSkewSeconds: 60,
  requireCompleteCaptures: false,
  allowedSources: null,
};
function safeInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error(`Invalid ${label}.`);
  return value;
}
function safeText(value: unknown, label: string, maximum = 256): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
  return value;
}
function safeDate(value: unknown, label: string): number {
  if (typeof value !== "string") throw new Error(`Invalid ${label}.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
    throw new Error(`Invalid ${label}.`);
  return parsed;
}
function validatePolicy(policy: BundlePolicy): BundlePolicy {
  safeInteger(policy.maximumCaptures, 1, 10000, "bundle capture limit");
  safeInteger(policy.maximumBytes, 1024, 50_000_000, "bundle byte limit");
  safeInteger(policy.maximumAgeSeconds, 1, 604800, "bundle age limit");
  safeInteger(policy.allowedClockSkewSeconds, 0, 3600, "bundle clock skew");
  if (typeof policy.requireCompleteCaptures !== "boolean")
    throw new Error("Invalid bundle completeness requirement.");
  if (policy.allowedSources !== null) {
    if (!Array.isArray(policy.allowedSources) || policy.allowedSources.length > 1000)
      throw new Error("Invalid bundle source allowlist.");
    const sources = new Set(policy.allowedSources.map(source =>
      safeText(source, "bundle source", 1000)));
    if (sources.size !== policy.allowedSources.length)
      throw new Error("Duplicate bundle source allowlist entry.");
  }
  return policy;
}
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value))
      throw new Error("Non-finite canonical value.");
    if (typeof value === "undefined" || typeof value === "function")
      throw new Error("Unsupported canonical value.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key =>
    JSON.stringify(key) + ":" + canonical(record[key])).join(",") + "}";
}
function unsigned(bundle: AuthenticatedBundle): unknown {
  return {
    format: bundle.format, version: bundle.version,
    organizationId: bundle.organizationId,
    createdAt: bundle.createdAt, expiresAt: bundle.expiresAt,
    nonce: bundle.nonce, captures: bundle.captures,
    manifest: bundle.manifest,
    keyId: bundle.signature.keyId,
    algorithm: bundle.signature.algorithm,
  };
}
function mac(value: unknown, key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.byteLength < 32)
    throw new Error("Bundle signing key must be at least 32 bytes.");
  return createHmac("sha256", key).update(canonical(value), "utf8").digest("hex");
}
function sameDigest(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}
function normalizedCaptures(
  input: readonly unknown[], organizationId: string, policy: BundlePolicy,
): CaseSnapshot[] {
  if (input.length > policy.maximumCaptures)
    throw new Error("Bundle capture limit exceeded.");
  const allowed = policy.allowedSources === null ? null : new Set(policy.allowedSources);
  const captures = input.map(value => parseCaseSnapshot(value));
  const seen = new Set<string>();
  for (const capture of captures) {
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization bundle capture forbidden.");
    if (allowed && !allowed.has(capture.source))
      throw new Error("Bundle contains a source outside the allowlist.");
    if (policy.requireCompleteCaptures && !capture.complete)
      throw new Error("Bundle requires complete captures.");
    const identity = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
    if (seen.has(identity)) throw new Error("Duplicate bundle capture identity.");
    seen.add(identity);
  }
  return captures.sort((a, b) => a.source.localeCompare(b.source) ||
    a.capturedAt.localeCompare(b.capturedAt));
}
export function createAuthenticatedSnapshotBundle(
  input: readonly unknown[], organizationId: string, key: BundleKey,
  createdAt: string, expiresAt: string, nonce: string,
  policy: BundlePolicy = DEFAULT_BUNDLE_POLICY,
): AuthenticatedBundle {
  validatePolicy(policy);
  safeText(organizationId, "organization ID");
  safeText(key.id, "bundle key ID");
  safeText(nonce, "bundle nonce", 128);
  if (key.revoked) throw new Error("Revoked bundle signing key.");
  const created = safeDate(createdAt, "creation time");
  const expires = safeDate(expiresAt, "expiry time");
  const activeFrom = safeDate(key.activeFrom, "key activation time");
  const activeUntil = key.activeUntil === null ? Infinity :
    safeDate(key.activeUntil, "key retirement time");
  if (created < activeFrom || created >= activeUntil)
    throw new Error("Bundle signing key is not active at creation time.");
  if (expires <= created || expires - created > policy.maximumAgeSeconds * 1000)
    throw new Error("Bundle validity exceeds configured lifetime.");
  const captures = normalizedCaptures(input, organizationId, policy);
  const manifest = buildSnapshotManifest(captures, organizationId, createdAt);
  const bundle: AuthenticatedBundle = {
    format: "cyberpilot-snapshot-bundle", version: 1,
    organizationId, createdAt, expiresAt, nonce, captures, manifest,
    signature: { algorithm: "HMAC-SHA256", keyId: key.id, digest: "" },
  };
  const payload = canonical(unsigned(bundle));
  if (Buffer.byteLength(payload, "utf8") > policy.maximumBytes)
    throw new Error("Bundle exceeds maximum serialized size.");
  bundle.signature.digest = mac(unsigned(bundle), key.secret);
  return bundle;
}
export function verifyAuthenticatedSnapshotBundle(
  raw: unknown, organizationId: string, keyring: BundleKeyring,
  evaluatedAt: string, replayLedger?: BundleReplayLedger,
  policy: BundlePolicy = DEFAULT_BUNDLE_POLICY,
): BundleValidation {
  validatePolicy(policy);
  const now = safeDate(evaluatedAt, "verification time");
  const base: BundleValidation = {
    verified: false, code: "MALFORMED", organizationId,
    keyId: null, manifestRoot: null, captureCount: 0,
    createdAt: null, expiresAt: null,
    warnings: [
      "HMAC authentication depends on an independently trusted, protected keyring.",
      "Verification does not prove the truth of security findings or remediation outcomes.",
      "Replay prevention requires a durable, atomically updated nonce ledger.",
    ],
  };
  const failure = (code: BundleValidationCode): BundleValidation => ({ ...base, code });
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    return failure("MALFORMED");
  const bundle = raw as AuthenticatedBundle;
  if (bundle.format !== "cyberpilot-snapshot-bundle" || bundle.version !== 1 ||
      !bundle.signature || bundle.signature.algorithm !== "HMAC-SHA256" ||
      !Array.isArray(bundle.captures))
    return failure("MALFORMED");
  if (bundle.organizationId !== organizationId)
    return failure("WRONG_ORGANIZATION");
  let created: number;
  let expires: number;
  let key: BundleKey | null;
  try {
    safeText(bundle.signature.keyId, "bundle key ID");
    safeText(bundle.nonce, "bundle nonce", 128);
    created = safeDate(bundle.createdAt, "creation time");
    expires = safeDate(bundle.expiresAt, "expiry time");
    if (expires <= created || expires - created > policy.maximumAgeSeconds * 1000)
      return failure("MALFORMED");
    if (bundle.captures.length > policy.maximumCaptures)
      return failure("CAPTURE_POLICY");
    key = keyring.getKey(organizationId, bundle.signature.keyId);
  } catch {
    return failure("MALFORMED");
  }
  if (!key || key.revoked || key.id !== bundle.signature.keyId)
    return failure("UNTRUSTED_KEY");
  try {
    const from = safeDate(key.activeFrom, "key activation");
    const until = key.activeUntil === null ? Infinity :
      safeDate(key.activeUntil, "key retirement");
    if (created < from || created >= until)
      return failure("UNTRUSTED_KEY");
    const payload = canonical(unsigned(bundle));
    if (Buffer.byteLength(payload, "utf8") > policy.maximumBytes)
      return failure("CAPTURE_POLICY");
    const expected = mac(unsigned(bundle), key.secret);
    if (!sameDigest(expected, bundle.signature.digest))
      return failure("INVALID_SIGNATURE");
  } catch {
    return failure("MALFORMED");
  }
  if (now + policy.allowedClockSkewSeconds * 1000 < created)
    return failure("FUTURE");
  if (now - policy.allowedClockSkewSeconds * 1000 >= expires)
    return failure("EXPIRED");
  if (replayLedger?.hasSeen(organizationId, key.id, bundle.nonce))
    return failure("REPLAYED");
  let captures: CaseSnapshot[];
  try {
    captures = normalizedCaptures(bundle.captures, organizationId, policy);
    const actual = buildSnapshotManifest(captures, organizationId, bundle.createdAt);
    if (bundle.manifest.organizationId !== organizationId ||
        !sameDigest(actual.rootSha256, bundle.manifest.rootSha256))
      return failure("MANIFEST_CHANGED");
    if (actual.entries.length !== bundle.manifest.entries.length)
      return failure("MANIFEST_CHANGED");
    for (let i = 0; i < actual.entries.length; i++)
      if (canonical(actual.entries[i]) !== canonical(bundle.manifest.entries[i]))
        return failure("MANIFEST_CHANGED");
  } catch {
    return failure("CAPTURE_POLICY");
  }
  return {
    ...base, verified: true, code: "VERIFIED",
    keyId: key.id, manifestRoot: bundle.manifest.rootSha256,
    captureCount: captures.length, createdAt: bundle.createdAt,
    expiresAt: bundle.expiresAt,
  };
}
export function fingerprintAuthenticatedBundle(bundle: AuthenticatedBundle): string {
  return createHash("sha256").update(canonical(unsigned(bundle)), "utf8").digest("hex");
}
