import { describe, expect, it } from "vitest";
import {
  configuredDispatchKeys, inspectDispatchConfiguration,
  parseDispatchKeyConfig, parseSignedDispatchIntent,
  signOsvDispatch, signedDispatchCanonical,
  validateSignedDispatchTime, verifyDispatchSignature,
  verifySignedDispatch,
} from "./assets-osv-signed-dispatch";

const now = new Date("2026-11-10T12:00:00.000Z");
const key = {
  id: "osv-key-production-01",
  organizationId: "organization-12345",
  secretHex: "a1".repeat(32),
};
const second = {
  id: "osv-key-other-tenant",
  organizationId: "other-organization-12345",
  secretHex: "c3".repeat(32),
};
const intent = {
  schema: "cyberpilot.assets.osv.signed-dispatch.v1",
  organizationId: key.organizationId,
  organizationSlug: "organization-12345",
  scheduleId: "osv-schedule-12345",
  expectedRevision: 3,
  issuedAt: "2026-11-10T11:59:30.000Z",
  expiresAt: "2026-11-10T12:01:00.000Z",
  nonce: "random-nonce-alpha-1234567890",
  confirmDispatch: true,
} as const;
const parse = () => parseSignedDispatchIntent(intent);
const config = { enabled: true, keys: [key, second] };
const signature = () => signOsvDispatch(parse(), key.secretHex);

describe("signed OSV worker protocol and bounded configuration", () => {
  it("is disabled with no installed credentials by default", () => {
    expect(parseDispatchKeyConfig(undefined, undefined))
      .toEqual({ enabled: false, keys: [] });
    expect(parseDispatchKeyConfig("false", "not-json"))
      .toEqual({ enabled: false, keys: [] });
  });
  it("rejects enabled dispatch without valid key configuration", () => {
    expect(() => parseDispatchKeyConfig("true", undefined)).toThrow();
    expect(() => parseDispatchKeyConfig("true", "invalid JSON")).toThrow();
    expect(() => parseDispatchKeyConfig("yes", "[]")).toThrow();
    expect(() => parseDispatchKeyConfig("true", "[]")).toThrow();
  });
  it("requires precisely 256-bit tenant-specific secrets", () => {
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      { ...key, secretHex: "short" },
    ]))).toThrow();
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      { ...key, secretHex: "GG".repeat(32) },
    ]))).toThrow();
    expect(parseDispatchKeyConfig("true",
      JSON.stringify([key]))).toEqual({
      enabled: true, keys: [key],
    });
  });
  it("rejects duplicate key IDs even across organizations", () => {
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      key, { ...second, id: key.id },
    ]))).toThrow();
  });
  it("rejects unexpected key fields without persisting credentials", () => {
    expect(() => parseDispatchKeyConfig("true", JSON.stringify([
      { ...key, canOverrideQuota: true },
    ]))).toThrow();
  });
  it("enforces the exact signed protocol version and all required IDs", () => {
    expect(parse().schema).toBe(intent.schema);
    expect(() => parseSignedDispatchIntent({
      ...intent, schema: "cyberpilot.osv.legacy",
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, scheduleId: "short",
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, organizationSlug: "bad/slug",
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, extra: true,
    })).toThrow();
  });
  it("requires explicit dispatch consent in the signed payload", () => {
    expect(() => parseSignedDispatchIntent({
      ...intent, confirmDispatch: false,
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, confirmDispatch: null,
    })).toThrow();
  });
  it("requires a positive safe schedule revision", () => {
    for (const expectedRevision of [0, -1, 1.5, NaN, Infinity,
      Number.MAX_SAFE_INTEGER]) {
      expect(() => parseSignedDispatchIntent({
        ...intent, expectedRevision,
      })).toThrow();
    }
  });
  it("requires cryptographically random-length nonce syntax", () => {
    expect(() => parseSignedDispatchIntent({
      ...intent, nonce: "short",
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, nonce: "malicious\nnonce-is-not-safe",
    })).toThrow();
  });
  it("rejects malformed calendar dates and noncanonical timestamps", () => {
    expect(() => parseSignedDispatchIntent({
      ...intent, issuedAt: "2026-11-10T12:00:00Z",
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, issuedAt: "2026-02-30T12:00:00.000Z",
    })).toThrow();
  });
  it("limits the signed validity interval to two minutes", () => {
    expect(() => parseSignedDispatchIntent({
      ...intent, expiresAt: "2026-11-10T12:01:31.000Z",
    })).toThrow();
    expect(() => parseSignedDispatchIntent({
      ...intent, expiresAt: intent.issuedAt,
    })).toThrow();
  });
  it("verifies valid signed requests using constant-time byte comparison", () => {
    expect(verifyDispatchSignature(parse(), key, signature())).toBe(true);
    expect(verifySignedDispatch(parse(), key.id, signature(),
      config, now)).toMatchObject({
      organizationId: key.organizationId,
      scheduleId: intent.scheduleId,
      expectedRevision: 3,
      keyId: key.id,
    });
  });
  it("rejects missing, shortened, malformed and incorrect signatures", () => {
    expect(verifyDispatchSignature(parse(), key, null)).toBe(false);
    expect(verifyDispatchSignature(parse(), key, "f")).toBe(false);
    expect(verifyDispatchSignature(parse(), key, "GG".repeat(32)))
      .toBe(false);
    expect(verifyDispatchSignature(parse(), key, "f".repeat(64)))
      .toBe(false);
  });
  it("binds signatures to every security-critical request property", () => {
    const baseline = signedDispatchCanonical(parse());
    const altered = [
      { ...intent, scheduleId: "another-schedule-12345" },
      { ...intent, expectedRevision: 4 },
      { ...intent, organizationId: second.organizationId },
      { ...intent, nonce: "random-nonce-other-1234567890" },
      { ...intent, expiresAt: "2026-11-10T12:00:30.000Z" },
    ];
    for (const change of altered) {
      const item = parseSignedDispatchIntent(change);
      expect(signedDispatchCanonical(item)).not.toBe(baseline);
      expect(verifyDispatchSignature(item, key, signature())).toBe(false);
    }
  });
  it("rejects cross-tenant signatures even with a matching key secret", () => {
    const foreign = parseSignedDispatchIntent({
      ...intent, organizationId: second.organizationId,
    });
    expect(verifyDispatchSignature(foreign, key,
      signOsvDispatch(foreign, key.secretHex))).toBe(false);
    expect(() => verifySignedDispatch(foreign, key.id,
      signOsvDispatch(foreign, key.secretHex), config, now)).toThrow();
  });
  it("rejects unknown, rotated-out and other tenant key identities", () => {
    expect(() => verifySignedDispatch(parse(), "unknown-key-12345",
      signature(), config, now)).toThrow();
    expect(() => verifySignedDispatch(parse(), second.id,
      signature(), config, now)).toThrow();
  });
  it("rejects invalid disabled configuration before accepting a signature", () => {
    expect(() => verifySignedDispatch(parse(), key.id, signature(), {
      enabled: false, keys: [key],
    }, now)).toThrow();
  });
  it("rejects requests issued more than thirty seconds in the future", () => {
    const future = parseSignedDispatchIntent({
      ...intent,
      issuedAt: "2026-11-10T12:00:31.000Z",
      expiresAt: "2026-11-10T12:02:00.000Z",
    });
    expect(() => validateSignedDispatchTime(future, now)).toThrow();
  });
  it("rejects expired signatures and acceptance outside the clock window", () => {
    expect(() => validateSignedDispatchTime(parse(),
      new Date("2026-11-10T12:01:01.000Z"))).toThrow();
    expect(() => validateSignedDispatchTime(parse(),
      new Date("2026-11-10T11:58:30.000Z"))).toThrow();
    expect(() => validateSignedDispatchTime(parse(), now)).not.toThrow();
  });
  it("never claims the runtime worker is installed based on key configuration", () => {
    const report = inspectDispatchConfiguration(config,
      key.organizationId);
    expect(report).toMatchObject({
      enabled: true, hasTenantKey: true, scopedKeys: 2,
      replayStorage: "POSTGRESQL", installsCron: false,
      grantsScheduleCreation: false,
      grantsConsentModification: false,
      grantsQuotaOverride: false,
    });
    expect(report.eligibleKeyIds).toEqual([key.id]);
    expect(report).not.toHaveProperty("secretHex");
  });
  it("produces no eligible keys for another tenant or disabled state", () => {
    const disabled = inspectDispatchConfiguration({
      enabled: false, keys: [key],
    }, key.organizationId);
    expect(disabled.hasTenantKey).toBe(false);
    const unknown = inspectDispatchConfiguration(config,
      "unrecognized-org-12345");
    expect(unknown.eligibleKeyIds).toEqual([]);
  });
});
