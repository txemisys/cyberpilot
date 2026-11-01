import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import { buildSnapshotManifest, verifySnapshotManifest, type SnapshotManifest } from "./work-integrity-snapshot-integrity";

/**
 * Authenticated transfer envelopes for offline case snapshots.
 * HMAC authenticates a payload only when the signing key is independently
 * provisioned and kept outside the payload. It is not a digital signature.
 */
export type SnapshotTransferEnvelope = {
  version: 1;
  algorithm: "HMAC-SHA256";
  organizationId: string;
  keyId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  manifest: SnapshotManifest;
  captures: CaseSnapshot[];
  signature: string;
};
export type TransferVerificationCode =
  | "VERIFIED" | "INVALID_SIGNATURE" | "EXPIRED" | "NOT_YET_VALID"
  | "TENANT_MISMATCH" | "MANIFEST_MISMATCH" | "KEY_MISMATCH"
  | "REPLAY" | "INVALID_ENVELOPE";
export type TransferVerification = {
  verified: boolean;
  code: TransferVerificationCode;
  organizationId: string;
  keyId: string;
  manifestRoot: string;
  captureCount: number;
  expiresAt: string;
  warnings: string[];
};
export type TransferSigningPolicy = {
  maxLifetimeSeconds: number;
  maxCaptures: number;
  maxSerializedBytes: number;
  clockSkewSeconds: number;
};
export type TransferReplayStore = {
  hasNonce(organizationId: string, keyId: string, nonce: string): boolean;
};
const DEFAULT_POLICY: TransferSigningPolicy = {
  maxLifetimeSeconds: 86400,
  maxCaptures: 1000,
  maxSerializedBytes: 5_000_000,
  clockSkewSeconds: 60,
};
function integer(value: number, min: number, max: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`Invalid ${name}.`);
  return value;
}
function validated(policy: TransferSigningPolicy): TransferSigningPolicy {
  return {
    maxLifetimeSeconds: integer(policy.maxLifetimeSeconds, 1, 604800, "transfer lifetime"),
    maxCaptures: integer(policy.maxCaptures, 1, 10000, "transfer capture limit"),
    maxSerializedBytes: integer(policy.maxSerializedBytes, 1024, 50_000_000, "transfer byte limit"),
    clockSkewSeconds: integer(policy.clockSkewSeconds, 0, 3600, "transfer clock skew"),
  };
}
function required(value: string, label: string, max = 256): string {
  if (typeof value !== "string" || !value.trim() || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
  return value;
}
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key =>
    JSON.stringify(key) + ":" + canonical(record[key])).join(",") + "}";
}
function payload(envelope: Omit<SnapshotTransferEnvelope, "signature">): string {
  return canonical({
    version: envelope.version, algorithm: envelope.algorithm,
    organizationId: envelope.organizationId, keyId: envelope.keyId,
    issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt,
    nonce: envelope.nonce, manifest: envelope.manifest,
    captures: envelope.captures,
  });
}
function hmac(message: string, secret: string): string {
  return createHmac("sha256", secret).update(message, "utf8").digest("hex");
}
function validateSecret(secret: string): void {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32)
    throw new Error("Transfer signing key must contain at least 32 UTF-8 bytes.");
}
function iso(value: string, label: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    throw new Error(`Invalid ${label}.`);
  return new Date(value).toISOString();
}
export function createSnapshotTransferEnvelope(
  capturesInput: readonly unknown[], organizationId: string,
  keyId: string, secret: string, issuedAt: string,
  expiresAt: string, nonce: string,
  policy: TransferSigningPolicy = DEFAULT_POLICY,
): SnapshotTransferEnvelope {
  const limits = validated(policy);
  required(organizationId, "organization ID");
  required(keyId, "key ID");
  required(nonce, "nonce", 128);
  validateSecret(secret);
  if (capturesInput.length > limits.maxCaptures)
    throw new Error("Transfer capture limit exceeded.");
  const issued = iso(issuedAt, "issue timestamp");
  const expires = iso(expiresAt, "expiry timestamp");
  const duration = (Date.parse(expires) - Date.parse(issued)) / 1000;
  if (duration <= 0 || duration > limits.maxLifetimeSeconds)
    throw new Error("Transfer expiry violates the lifetime policy.");
  const captures = capturesInput.map(value => parseCaseSnapshot(value));
  for (const capture of captures)
    if (capture.organizationId !== organizationId)
      throw new Error("Cross-organization transfer capture is forbidden.");
  const manifest = buildSnapshotManifest(captures, organizationId, issued);
  const unsigned = {
    version: 1 as const, algorithm: "HMAC-SHA256" as const,
    organizationId, keyId, issuedAt: issued, expiresAt: expires,
    nonce, manifest, captures,
  };
  const serialized = payload(unsigned);
  if (Buffer.byteLength(serialized, "utf8") > limits.maxSerializedBytes)
    throw new Error("Transfer payload exceeds byte budget.");
  return { ...unsigned, signature: hmac(serialized, secret) };
}
export function verifySnapshotTransferEnvelope(
  envelope: SnapshotTransferEnvelope, organizationId: string,
  keyId: string, secret: string, now: string,
  replayStore?: TransferReplayStore,
  policy: TransferSigningPolicy = DEFAULT_POLICY,
): TransferVerification {
  const limits = validated(policy);
  validateSecret(secret);
  const current = Date.parse(now);
  if (!Number.isFinite(current)) throw new Error("Invalid verification time.");
  const base = {
    organizationId, keyId, manifestRoot: "", captureCount: 0,
    expiresAt: "", warnings: [
      "HMAC verification authenticates possession of the shared key, not the identity of a human reviewer.",
      "A verified transfer does not establish the accuracy of the underlying security diagnostics.",
    ],
  };
  const fail = (code: TransferVerificationCode): TransferVerification =>
    ({ ...base, verified: false, code });
  if (!envelope || envelope.version !== 1 ||
      envelope.algorithm !== "HMAC-SHA256" ||
      typeof envelope.organizationId !== "string" ||
      typeof envelope.keyId !== "string" ||
      typeof envelope.signature !== "string" ||
      !/^[0-9a-f]{64}$/.test(envelope.signature) ||
      !Array.isArray(envelope.captures) ||
      envelope.captures.length > limits.maxCaptures)
    return fail("INVALID_ENVELOPE");
  if (envelope.organizationId !== organizationId)
    return fail("TENANT_MISMATCH");
  if (envelope.keyId !== keyId)
    return fail("KEY_MISMATCH");
  let issued: number;
  let expires: number;
  try {
    issued = Date.parse(iso(envelope.issuedAt, "issuedAt"));
    expires = Date.parse(iso(envelope.expiresAt, "expiresAt"));
    required(envelope.nonce, "nonce", 128);
    if (expires <= issued ||
        expires - issued > limits.maxLifetimeSeconds * 1000)
      return fail("INVALID_ENVELOPE");
  } catch {
    return fail("INVALID_ENVELOPE");
  }
  const unsigned = {
    version: envelope.version, algorithm: envelope.algorithm,
    organizationId: envelope.organizationId, keyId: envelope.keyId,
    issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt,
    nonce: envelope.nonce, manifest: envelope.manifest,
    captures: envelope.captures,
  };
  let serialized: string;
  try {
    serialized = payload(unsigned);
    if (Buffer.byteLength(serialized, "utf8") > limits.maxSerializedBytes)
      return fail("INVALID_ENVELOPE");
  } catch {
    return fail("INVALID_ENVELOPE");
  }
  const expected = Buffer.from(hmac(serialized, secret), "hex");
  const received = Buffer.from(envelope.signature, "hex");
  if (!timingSafeEqual(expected, received)) return fail("INVALID_SIGNATURE");
  if (current < issued - limits.clockSkewSeconds * 1000)
    return fail("NOT_YET_VALID");
  if (current >= expires + limits.clockSkewSeconds * 1000)
    return fail("EXPIRED");
  if (replayStore?.hasNonce(organizationId, keyId, envelope.nonce))
    return fail("REPLAY");
  try {
    if (envelope.manifest.organizationId !== organizationId ||
        !verifySnapshotManifest(envelope.manifest, envelope.captures).verified)
      return fail("MANIFEST_MISMATCH");
  } catch {
    return fail("MANIFEST_MISMATCH");
  }
  return {
    ...base, verified: true, code: "VERIFIED",
    manifestRoot: envelope.manifest.rootSha256,
    captureCount: envelope.captures.length,
    expiresAt: envelope.expiresAt,
  };
}
export function transferEnvelopeFingerprint(envelope: SnapshotTransferEnvelope): string {
  return createHash("sha256").update(payload({
    version: envelope.version, algorithm: envelope.algorithm,
    organizationId: envelope.organizationId, keyId: envelope.keyId,
    issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt,
    nonce: envelope.nonce, manifest: envelope.manifest, captures: envelope.captures,
  }), "utf8").digest("hex");
}
